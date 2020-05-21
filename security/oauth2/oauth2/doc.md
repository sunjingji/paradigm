OAuth 的核心就是向第三方应用颁发令牌。
OAuth 2.0(RFC6749) 规定了四种获得令牌的流程。你可以选择最适合自己的那一种，向第三方应用颁发令牌。下面就是这四种授权方式。
    授权码（authorization-code）
    隐藏式（implicit）
    密码式（password）：
    客户端凭证（client credentials）
注意，不管哪一种授权方式，第三方应用申请令牌之前，都必须先到系统备案，说明自己的身份，然后会拿到两个身份识别码：客户端 ID（client ID）和客户端密钥（client secret）。
这是为了防止令牌被滥用，没有备案过的第三方应用，是不会拿到令牌的。


OAuth2.0 授权码授权流程如下，参考图：oauth2.png。
1. 申请授权码
客户端把用户导向微博授权服务器。
例如：
    HTTP/1.1 302 Found
    Location: https://weibo.com/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https://weiboclient.com/cb

客户端申请认证的URI，包含以下参数：
    response_type：表示授权类型，必选项，此处的值固定为"code"
    client_id：表示客户端的ID，必选项
    redirect_uri：表示重定向URI，可选项
    scope：表示申请的权限范围，可选项
    state：表示客户端的当前状态，可以指定任意值，可选项。
例如：

2. 返回授权码
微博授权服务器响应客户端的URI，包含以下参数：
    code：表示授权码，必选项。该码的有效期应该很短，通常设为10分钟，客户端只能使用该码一次，否则会被授权服务器拒绝。该码与客户端ID和重定向URI，是一一对应关系。
    state：如果客户端的请求中包含这个参数，认证服务器的回应也必须一模一样包含这个参数。
例如：
    HTTP/1.1 302 Found
    Location: https://weiboclient.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz

3. 请求令牌
客户端的后台服务器发现这个特殊的跳转Url，向资源服务器申请令牌。
客户端向认证服务器申请令牌的HTTP请求，包含以下参数：
    grant_type：表示使用的授权模式，此处的值固定为"authorization_code"。
    code：表示上一步获得的授权码
    redirect_uri：表示重定向URI，且必须与A步骤中的该参数值保持一致。
    client_id：表示客户端ID
    client_secret:客户端密钥
例如：
    POST /token HTTP/1.1
    Host: weibo.com
    Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https://weiboclient.com/cb

4. 返回令牌
维护授权服务器发送的HTTP回复，包含以下参数：
    access_token：表示访问令牌，必选项。
    token_type：表示令牌类型，该值大小写不敏感，必选项，可以是bearer类型或mac类型。
    expires_in：表示过期时间，单位为秒。如果省略该参数，必须其他方式设置过期时间。
    refresh_token：表示更新令牌，用来获取下一次的访问令牌，可选项。
    scope：表示权限范围，如果与客户端申请的范围一致，此项可省略。
例如：
    HTTP/1.1 200 OK
    Content-Type: application/json;charset=UTF-8
    Cache-Control: no-store
    Pragma: no-cache

    {
      "access_token":"2YotnFZFEjr1zCsicMWpAA",
      "token_type":"Bearer",
      "expires_in":3600,
      "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
    }
从上面代码可以看到，相关参数使用JSON格式发送（Content-Type: application/json）。此外，HTTP头信息中明确指定不得缓存。

参考：
  Oauth2              https://tools.ietf.org/html/rfc6749
  Oauth2 Bear Token   https://tools.ietf.org/html/rfc6750
  Oauth2的一个解释      http://www.ruanyifeng.com/blog/2019/04/oauth_design.html
  OAuth2的四种授权方式   http://www.ruanyifeng.com/blog/2019/04/oauth-grant-types.html
  Web应用登录阿里云      https://helpcdn.aliyun.com/document_detail/93696.html

注1: 阿里云针对Native应用登录，引入了Proof Key机制的原理，即使用code_verifier代替client_secret。
注2：OIDC（OpenID Connect）是建立在OAuth 2.0基础上的一个认证协议，参考阿里云通过OIDC获取用户信息的文档。