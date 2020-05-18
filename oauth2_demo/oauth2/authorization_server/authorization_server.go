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
	"time"
)

func main() {
	manager := manage.NewDefaultManager()
	cfg := manage.DefaultAuthorizeCodeTokenCfg
	cfg.AccessTokenExp = time.Second*100
	//manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
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
