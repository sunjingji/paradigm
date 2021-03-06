## 1. Web安全漏洞

### 1.1 XSS 跨站脚本攻击
XSS的原理是恶意攻击者想尽一切办法，向Web页面里注入可执行的js代码，当用户浏览该页之时，嵌入其中的js代码会被执行。

注入可能发生在服务端，也可能发生在客户端，常见防范的方法：

  - 转义字符   
    用户的输入永远不可信任的，最普遍的做法就是转义输入输出的内容，对于引号、尖括号、斜杠进行转义。

  - CSP  
    CSP本质上就是建立白名单，开发者明确告诉浏览器哪些外部资源可以加载和执行。我们只需要配置规则，如何拦截是由浏览器自己实现的，通过这种方式可以尽量减少 XSS 攻击。
  
        通常可以通过两种方式来开启 CSP：
        - 设置 HTTP Header 中的 Content-Security-Policy  
        - 设置 meta 标签的方式

  - HttpOnly Cookie  
    这是预防XSS攻击窃取用户cookie最有效的防御手段。Web应用程序在设置cookie时，将其属性设为HttpOnly，就可以避免该网页的cookie被客户端恶意JavaScript窃取，保护用户cookie信息。

### 1.2 CSRF
CSRF(Cross Site Request Forgery)，即跨站请求伪造，是一种常见的Web攻击，它利用用户已登录的身份，在用户毫不知情的情况下，以用户的名义完成非法操作。
CSRF的原理参考图： csrf.png

防范 CSRF 攻击可以遵循以下几种规则：  

- Get 请求不对数据进行修改
- 不让第三方网站访问到用户 Cookie
- 阻止第三方网站请求接口
- 请求时附带验证信息，比如验证码或者 Token


### 1.3 点击劫持
点击劫持是一种视觉欺骗的攻击手段。攻击者将需要攻击的网站通过 iframe 嵌套的方式嵌入自己的网页中，并将 iframe 设置为透明，在页面中透出一个按钮诱导用户点击。

X-FRAME-OPTIONS 是一个 HTTP 响应头，在现代浏览器有一个很好的支持，可以防范iframe嵌套的点击劫持。
该响应头有三个值可选，分别是：

- DENY，表示页面不允许通过 iframe 的方式展示
- SAMEORIGIN，表示页面可以在相同域名下通过 iframe 的方式展示
- ALLOW-FROM，表示页面可以在指定来源的 iframe 中展示

### 1.4 SQL注入
SQL注入是一种常见的Web安全漏洞，攻击者利用这个漏洞，可以访问或修改数据，或者利用潜在的数据库漏洞进行攻击。

如何防御:

- 严格限制Web应用的数据库的操作权限，给此用户提供仅仅能够满足其工作的最低权限，从而最大限度的减少注入攻击对数据库的危害。
- 后端代码检查输入的数据是否符合预期，严格限制变量的类型，例如使用正则表达式进行一些匹配处理。
- 对进入数据库的特殊字符（'，"，，<，>，&，*，; 等）进行转义处理，或编码转换。
- 所有的查询语句建议使用数据库提供的参数化查询接口，参数化的语句使用参数而不是将用户输入变量嵌入到 SQL 语句中，即不要直接拼接 SQL 语句。例如 Node.js 中的 mysqljs 库的 query 方法中的 ? 占位参数。

### 1.5 OS命令注入攻击
OS命令注入和SQL注入差不多，只不过SQL注入是针对数据库的，而OS命令注入是针对操作系统的。OS命令注入攻击指通过Web应用，执行非法的操作系统命令达到攻击的目的。只要在能调用Shell函数的地方就有存在被攻击的风险。倘若调用Shell时存在疏漏，就可以执行插入的非法命令。  

如何防御：

- 后端对前端提交内容进行规则限制（比如正则表达式）。
- 在调用系统命令前对所有传入参数进行命令行参数转义过滤。
- 不要直接拼接命令语句，借助一些工具做拼接、转义预处理，例如 Node.js 的 shell-escape npm包。


## 2. 认证授权

在一般的业务场景中，用户要使用服务，首先要即"登录"，以便业务系统确认用户身份。

常见的登录方式有：

- 账号密码
- 手机号/短信验证码
- 第三方登录(oauth2)
- 扫码登录

业务系统确认用户身份后，会发放一个身份凭证，在凭证失效以前，用户只要出示这个凭证，业务系统就认可用户的身份，避免了需要用户频繁登录的问题。

**认证系统要回答的问题**：

- 身份凭证的格式，保存方式，在客户和业务系统间如何传递，怎么保证不被他人盗用，怎么防止凭证被篡改，这些就是认证系统要考虑的核心问题。
- 其次，认证系统如何与业务系统结合，怎么横向扩展，如何给开发人员提供方便使用的界面，这是认证系统的非功能需求。

### 2.1 基于Cookie和Session的认证
早期互联网以 web 为主，客户端是浏览器，所以 Cookie-Session 方式最那时候最常用的方式，直到现在，一些 web 网站依然用这种方式做认证。

这种实现方式的弊端也很明显：

- 只能在 web 场景下使用，如果是 APP 中，不能使用 cookie 的情况下就不能用了。
- 即使能在 web 场景下使用，也要考虑跨域问题，因为 cookie 不能跨域。
- cookie 存在 CSRF（跨站请求伪造）的风险。
- 如果是分布式服务，需要考虑 Session 同步问题。

为解决这些问题，可以对传统的Cookie和Session方案改造如下：

- 不用 cookie 做客户端存储，改用其他方式，web 下使用 local storage，APP 中使用客户端数据库，这样就实现了跨域，并且避免了 CSRF。

上面的方案虽然经过了改版，但还是需要客户端和服务器端维持一个状态信息，比如用Cookie换Session ,或者用Key换Redis的Value 信息。

### 2.2 Token 认证

Token 可以是无状态的，可以在多个服务间共享。

有一篇很不错的文章[Token认证的来龙去脉](https://segmentfault.com/a/1190000013010835)，可以读一下。

#### 2.2.1 JWT Token
基于Token的认证，比较常用的就是JWT。 JSON Web Token（JWT）是一个非常轻巧的规范，允许我们使用JWT在用户和服务器之间传递安全可靠的信息。

认证流程：

- 服务端将认证信息通过指定的算法（例如HS256）进行加密，例如对用户名和用户所属角色进行加密，加密私钥是保存在服务器端的，将加密后的结果发送给客户端，加密的字符串格式为三个"." 分隔的字符串 Token，分别对应头部、载荷与签名，头部和载荷都可以通过 base64 解码出来，签名部分不可以。
- 客户端拿到返回的 Token，存储到 local storage 或本地数据库。
- 下次客户端再次发起请求，将 Token 附加到 header 中。
- 服务端获取 header 中的 Token ，通过相同的算法对 Token 中的用户名和所属角色进行相同的加密验证，如果验证结果相同，则说明这个请求是正常的，没有被篡改。

Jwt 载荷部分可以存储业务相关的信息（非敏感的），例如用户信息、角色等。

**适用场景：JWT的主要优势在于使用无状态、可扩展的方式处理应用中的用户会话。服务端可以通过内嵌的声明信息，很容易地获取用户的会话信息，而不需要去访问用户或会话的数据库。在一个分布式的面向服务的框架中，这一点非常有用。**

**注意：服务端怎么知道请求的客户端是可信的呢？答案是服务端无法知道，只能验证JWT token是否被篡改过。 所以需要在一个安全的网络环境中使用token，例如Https。**

**参考**
  [Introduction to JSON Web Tokens](https://jwt.io/introduction/)
  [什么是 JWT -- JSON WEB TOKEN](https://www.jianshu.com/p/576dbf44b2ae)

#### 2.2.2 Oauth2 & OIDC
Oauth2 是一个授权框架，不像 JWT 只是一个生成和验证 Token 的协议，但 Oauth2 可以 和 JWT 一起使用。

Oauth2 授权通过后会发放一个AccessToken。可以按JWT格式构造AccessToken，在AccessToken中存储更多的授权信息，但Oauth2服务端必须保存未到期却已注销的 AccessToken 信息，以防备用户撤销或更改授权。

另外在使用OIDC的场景中，比如微信是基于oauth2授权的，用户扫码登录我需要微信授权，然后微信授权以后，用户也点击确认之后我就认定用户为合法用户，自己用jwt生成一个token给用户。 用户每次访问都带着token访问我。 在这里微信给我是授权，我给用户是认证。

**适用场景：如果设计的API要被不同的App使用，并且每个App使用的方式也不一样，使用OAuth2是个不错的选择。**

**一个安全小问题：为什么用OAuth2协议是安全的呢？**  
答：以OAuth2授权码流程为例，当resource owner允许客户端访问某些资源后，然后授权服务器会生成responseCode，并重定向到ClientA的某个链接中（链接中需要带responseCode）。这里完全不用担心responseCode被泄露，因为其他Client没有ClientA的Secret，所以根本无法使用这个responseCode。另一个安全前提是授权服务需开放HTTPS的接口，因为访问资源的请求必须携带AccessToken，在HTTP环境下，也是可能被截获的。

**Oauth2和OIDC的关系式什么?**  
这里有一篇文章，对OIDC说的非常透传，可以参考 [OIDC(OpenId Connect)身份认证(核心部分)](https://www.cnblogs.com/linianhui/archive/2017/05/30/openid-connect-core.html)。  
OIDC在Oauth2的基础上实现了身份认证，扩展了一个Id Token，用来标识用户身份。
Id Token是认证系统发放的可以验证真伪的用户身份令牌。oauth2发放的AccessToken是一个访问许可令牌。
一个是身份认证，一个是访问授权。  
Id Token不能包含太多信息，要不然太长了，来回传输不方便。通常通过UserInfo接口来提供用户的详细信息
，UserInfo是受Oauth2保护的，必须使用AccessToken来访问。

**单点登录**  
单点登录历史最悠久的协议是[SAML](https://www.jianshu.com/p/636c1ee16eba)，它是一个简单的
登录认证协议。  
基本流程：用户登录服务B时，服务B到用户身份提供方A去认证用户的身份，A验证用户的身份(如果用户还没有
没有登录，则要求用户初始账号/密码)，并响应服务B，服务B从认证响应当中提取服务B能识别的用户身份信息，
用户登录服务B完成。  
OIDC也可以用来实现单点登录，而且对移动端APP支持的更好。

#### 2.2.3 HMAC(AK/SK)
HMAC预先生成一个 access key（AK） 和 secure key（SK），然后通过签名的方式完成认证请求，这种方式可以避免传输 secure key，且大多数情况下签名只允许使用一次，避免了重放攻击。

比如我们要访问百度云的资源，百度云API是基于AK/SK认证的，我们首先要在百度云注册应用，并取得AK/SK，在API请求中要携带使用请求信息和AK/SK构造的认证码，服务器使用同样的数据构造认证码，通过比较认证码是否相同，来确定用户的身份。

**适用场景：API之间互相调用的认证。**

    Jwt和 HMAC结合实现跨系统调用  
    在平时开发中一种常见的场景是一个用户从服务A跳转到服务B，而且是带着服务A的认证（token或者cookie）过来，如果让用户从新登陆也不合适，常见的做法是：
        服务B获取服务A的token  
        服务B使用服务A预先分发的ak和sk，将token作为数据，使用HMAC算法计算签名
        服务B调用服务A的token认证解析接口
        服务A返回是否认证以及认证的结果
        服务B根据认证结果进行下一步操作

    Digest 认证
    HTTP Digetst认证方式，其实和HMAC思想是一样的，为了防止重放攻击，采用摘要访问认证。
    客户发送一个请求后，收到一个401消息，消息中还包括一个唯一的字符串：nonce，每次请求都不一样。
    此时客户端将用户名、密码、nonce、HTTP Method和URI为校验值基础进行散列（默认为MD5）的摘要返回给服务器。


插播：

    authentication 认证，证明你是你
    authorization  授权，允许你干什么

## 3. HTTPS
从上面对Web安全漏洞和认证授权的分析可以看出，无论怎么做，https都是安全的基础，现代的互联网应用应该完全摈弃裸奔的http。