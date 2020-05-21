package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

//
// 百度云API AK/SK 鉴权例子
//
// 百度云API AK/SK认证的原理是：Client使用AK/SK，对Http请求的Method、URL、QueryString、Header生成签名，Server接收到请求后也按同样的方式生成签名，然后对比两个签名是否相同。
// AK/SK认证字符串的目的主要是为了对API调用发起者进行身份验证，同时也有防止非法篡改，防止重放攻击的作用：
// 1)验证请求者的身份
//   签名可以确保请求是由某个具有有效访问密钥的用户或服务发起。
// 2)保护传输中的数据，防止非法篡改
//   若请求在传输过程中遭到非法篡改，由于第三方无法对篡改后的请求进行计算，得到新的认证字符串(Authorization)，Server收到请求后认证字符串匹配将失败，因此身份校验无法通过。
//   计算签名时，如果选择的Header太少，则可能遭到中间人攻击。百度云API建议至少选择：Host、Content-Length、Content-Type、Content-MD5、所有以x-bce-开头的Header。
// 3)防止重放攻击
//   认证字符串(Authorization)都具有指定的有效时间。如请求被截获，第三方无法在有效时间之外重放请求。
//
// 最佳实践：
// 1)临时授权
//   由于用户的移动端应用存在泄密的风险所以不可能直接存储AK/SK信息，必须使用STS临时授权模式访问BOS。
//   STS临时授权模式指定资源和权限，生成一个临时Token(包括临时AK/SK，SessionId，过期时间)，该Token具有一定的时效性，即APP应用只有在Token的时效性内访问才可以访问API，过了时效需要重新获取。
// 2)签名URL防盗链
//   Referer防盗链的优点是简单，缺点是无法防止恶意伪造Referer，如果盗链是通过应用程序模拟HTTP请求伪造Referer，则会绕过用户防盗链设置。如果对防盗链有更高要求的则需要通过签名URL实现防盗链。
//   签名URL防盗链的原理即将文件设为私有访问，然后生成一个预签名的URL，提供给用户一个临时的访问UEL。生成预签名URL时可以通过指定URL的有效时长限制用户长时间访问。
//
// 实现细节：
// 1)百度云API不直接使用用户SK对待签名串生成摘要，而是使用SK和前缀字符串生成派生签名密钥，然后使用派生密钥对规范请求生成最终签名摘要。
//   这样做的好处是可以把过期时间等加入前缀字符串中，为Server端提供额外的信息。
// 2)除了使用Authorization Header，用户还可以把认证字符串放到在URL中，具体方法是在URL的Query String中加入authorization = <认证字符串>
//
// 相关参考:
//   API入门指南 https://cloud.baidu.com/doc/APIGUIDE/s/1k1mysgan
//   鉴权认证机制 https://cloud.baidu.com/doc/Reference/s/Njwvz1wot
//   生成认证字符串 https://cloud.baidu.com/doc/Reference/s/njwvz1yfu#%E7%9B%B8%E5%85%B3%E5%87%BD%E6%95%B0%E8%AF%B4%E6%98%8E
//   临时授权访问 https://cloud.baidu.com/doc/BOS/s/Tjwvysda9#%E4%B8%B4%E6%97%B6%E6%8E%88%E6%9D%83%E8%AE%BF%E9%97%AE
//   最佳实践 https://cloud.baidu.com/doc/BOS/index.html
//
type BceSigner struct {
	AccessKey string
	SecretKey string
}

func NewBceSigner(accessKey string, secretKey string) *BceSigner {
	return &BceSigner{
		accessKey,
		secretKey,
	}
}

// 生成签名摘要
func (signer *BceSigner) buildAuthString(request *http.Request, expirationPeriodInSeconds int) string {
	authStringPrefix, signingKey := signer.buildSigningKey(request, expirationPeriodInSeconds)
	canonicalRequest, signedHeaders := signer.buildCanonicalRequest(request)
	signature := hmacSha256Hex(signingKey, canonicalRequest)
	return fmt.Sprintf("%s/%s/%s", authStringPrefix, signedHeaders, signature)
}

// 生成认证字符串前缀和派生密钥
func (signer *BceSigner) buildSigningKey(request *http.Request, expirationPeriodInSeconds int) (authStringPrefix string, signingKey string) {
	authStringPrefix = fmt.Sprintf("bce-signer-v1/%s/%s/%d", signer.AccessKey, request.Header.Get("x-bce-date"), expirationPeriodInSeconds)
	signingKey = hmacSha256Hex(signer.SecretKey, authStringPrefix)
	return
}

// 生成规范Request，确定signedHeaders
func (signer *BceSigner) buildCanonicalRequest(request *http.Request) (canonicalRequest string, signedHeaders string) {
	canonicalMethod := strings.ToUpper(request.Method)
	canonicalURI := signer.buildCanonicalURI(request.URL.Path)
	canonicalQuery := signer.buildCanonicalQueryString(request.URL.Query())
	canonicalHeaders, signedHeaders := signer.buildCanonicalHeaders(request.Header)
	canonicalRequest = fmt.Sprintf("%s\n%s\n%s\n%s", canonicalMethod, canonicalURI, canonicalQuery, canonicalHeaders)
	return
}

// 生成规范URI
func (signer *BceSigner) buildCanonicalURI(path string) string {
	if path == "" {
		path = "/"
	}
	path = url.QueryEscape(path)
	return strings.Replace(path, "%2F", "/", -1) // 按百度云API要求，斜杠（/）不做编码
}

// 生成规范QueryString
func (signer *BceSigner) buildCanonicalQueryString(query url.Values) string {
	kvs := make(sort.StringSlice, 0)
	for k, v := range query {
		if k == "authorization" {
			continue
		}
		kv := url.QueryEscape(k) + "=" + url.QueryEscape(v[0])
		kvs = append(kvs, kv)
	}
	kvs.Sort()
	return strings.Join(kvs, "&")
}

// 生成规范Headers，确定signedHeaders
func (signer *BceSigner) buildCanonicalHeaders(header http.Header) (canonicalHeaders string, signedHeaders string) {
	ks := make(sort.StringSlice, 0)
	kvs := make(sort.StringSlice, 0)
	for k, v := range header {
		keyStr := strings.ToLower(k)
		if keyStr == "host" ||
			keyStr == "content-length" ||
			keyStr == "content-type" ||
			keyStr == "content-md5" ||
			strings.Index(keyStr, "x-bce-") == 0 {
			var valStr string
			if len(v) != 0 {
				valStr = strings.Trim(v[0], "\t ")
			}
			if len(valStr) == 0 {
				continue
			}
			ks = append(ks, keyStr)
			kvs = append(kvs, fmt.Sprintf("%s:%s", keyStr, url.QueryEscape(valStr)))
		}
	}
	ks.Sort()
	signedHeaders = strings.Join(ks, ";")
	kvs.Sort()
	canonicalHeaders = strings.Join(kvs, "\n")
	return
}

// HMAC-SHA256-HEX
func hmacSha256Hex(key string, message string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

func main() {
	// 准备 url 和 request
	urlStr := "https://jowin-dev.bj.bcebos.com/meiyou"
	req, _ := http.NewRequest("GET", urlStr, nil)
	req.Header.Set("Host", "jowin-dev.bj.bcebos.com")
	req.Header.Set("x-bce-date", time.Now().UTC().Format("2006-01-02T15:04:05Z"))

	// 添加鉴权信息
	authBuilder := NewBceSigner("00862f7e445143478fa2b1483874d365", "31dab24594ca410d9ecd3d65874938cb")
	authString := authBuilder.buildAuthString(req, 1800)
	req.Header.Set("Authorization", authString)

	// 请求Object
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	if resp.StatusCode != 200 {
		fmt.Printf("get object failed, resp_code:%d\n", resp.StatusCode)
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("resp:\n%s\n", string(body))

	return
}