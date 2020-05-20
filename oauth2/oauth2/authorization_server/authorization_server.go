package main

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/errors"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
	"log"
	"net/http"
)

func main() {
	manager := manage.NewDefaultManager()
	cfg := manage.DefaultAuthorizeCodeTokenCfg
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	manager.SetAuthorizeCodeTokenCfg(cfg)

	// token memory store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// client memory store
	clientStore := store.NewClientStore()

	manager.MapClientStorage(clientStore)

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetAllowedGrantType(oauth2.AuthorizationCode)
	srv.SetAllowedResponseType(oauth2.Code, oauth2.Token)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	manager.SetRefreshTokenCfg(manage.DefaultRefreshTokenCfg)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	// 引导用户进行授权，需要业务代码实现
	// 这个函数是业务逻辑实现的关键，流程如下：
	// 1)第三方要求进行授权时，要依次检查用户是否已经登录，是否已对此应用做过授权。如果有未完成项(未登录或未授权)，先保存请求参数到session当中，然后跳转到相应登录/授权页面。
	// 2)取得用户授权后，需要返回userID(给上层的HandleAuthorizeRequest调用)。
	//
	// 注意：HandleAuthorizeRequest()后续生成授权码时，会调用AuthorizeScopeHandler设置授权域，调用AccessTokenExpHandler设置Token有效期。
	//      所以，需要在这个函数中提前做好簿记，把相关信息存储在某个位置，让AuthorizeScopeHandler和AccessTokenExpHandler可以访问到，这样才能把整个授权链串起来。
	// 参考 gopkg.in/oauth2.v3/example/server
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		return "demo", nil
	})

	// 发放客户端令牌，需要业务代码实现
	http.HandleFunc("/oauth/credential", func(w http.ResponseWriter, r *http.Request) {
		clientId := uuid.New().String()[:8]
		clientSecret := uuid.New().String()[:8]
		err := clientStore.Set(clientId, &models.Client{
			ID:     clientId,
			Secret: clientSecret,
			Domain: "http://localhost:9094",
		})
		if err != nil {
			fmt.Println(err.Error())
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"CLIENT_ID": clientId, "CLIENT_SECRET": clientSecret})
	})

	// 请求授权码
	http.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		srv.HandleAuthorizeRequest(w, r)
	})

	// 请求access_token
	http.HandleFunc("/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		srv.HandleTokenRequest(w, r)
	})

	// 访问资源
	http.HandleFunc("/resource", validateToken(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, I'm resource"))
	}, srv))

	log.Fatal(http.ListenAndServe(":9096", nil))
}

func validateToken(f http.HandlerFunc, srv *server.Server) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f.ServeHTTP(w, r)
	})
}
