/*
 在这个例子中，我们构造了一个简单的web应用，用户访问首页，使用GitHub账号登录，最终会在页面上看到的的UserInfo。
 因为需要提供redirect_uri, 我们使用花生壳构造了一个动态域名: jowinsoft.xicp.net

 演示 http://localhost:8080/index.html

 参考 https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps/
*/
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

// 在github注册应用，得到的ClientId和秘钥
const clientId = "fd77c6a620cb2ee846b4"
const clientSecret = "6e1577597d79ddc1cd0cd2fa31cd8c69341b4744"

// 使用code换取access_token
func GetAccessToken(code string) (token string, errCode int) {
	// Lets for the HTTP request to call the GitHub OAuth endpoint to get our access token
	reqURL := fmt.Sprintf("https://github.com/login/oauth/access_token?client_id=%s&client_secret=%s&code=%s", clientId, clientSecret, code)
	req, err := http.NewRequest(http.MethodPost, reqURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stdout, "could not create HTTP request: %v", err)
		errCode = http.StatusBadRequest
		return
	}
	// We set this header since we want the response as json
	req.Header.Set("accept", "application/json")

	// Send out the HTTP request
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stdout, "could not send HTTP request: %v", err)
		errCode = http.StatusInternalServerError
		return
	}
	defer resp.Body.Close()

	// Parse the request body into the `OAuthAccessResponse` struct
	var t OAuthAccessResponse
	body, _ := ioutil.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &t); err != nil {
		fmt.Fprintf(os.Stdout, "could not parse json response: %v", err)
		errCode = http.StatusBadRequest
		return
	}

	token = t.AccessToken
	errCode = http.StatusOK
	return
}

// 使用access_token,访问用户信息
func GetUserInfo(accessToken string) (user []byte, errCode int) {
	// Get user info and response with json format
	reqURL := fmt.Sprintf("https://api.github.com/user")
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stdout, "could not create HTTP request: %v", err)
		errCode = http.StatusBadRequest
		return
	}
	// We set this header since we need supply access_token
	req.Header.Set("authorization", "token "+accessToken)

	// Send out the HTTP request
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stdout, "could not send HTTP request: %v", err)
		errCode = http.StatusInternalServerError
		return
	}
	defer resp.Body.Close()

	user, _ = ioutil.ReadAll(resp.Body)
	errCode = http.StatusOK
	return
}

func main() {
	fs := http.FileServer(http.Dir("html"))
	http.Handle("/", fs)

	// Create a new redirect route
	http.HandleFunc("/oauth/redirect", func(w http.ResponseWriter, r *http.Request) {
		// First, we need to get the value of the `code` query param
		err := r.ParseForm()
		if err != nil {
			fmt.Fprintf(os.Stdout, "could not parse query: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		state := r.FormValue("state")
		if state != "abc" { // 来自第三方的恶意请求
			fmt.Fprintf(os.Stdout, "invalid request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Second, get access token
		token, errCode := GetAccessToken(code)
		if errCode != http.StatusOK {
			w.WriteHeader(errCode)
			return
		}

		// Finally, get user info
		user, errCode := GetUserInfo(token)
		w.WriteHeader(errCode)
		w.Header().Set("content-type", "application/json")
		w.Write(user)
	})

	http.ListenAndServe(":8080", nil)
}

type OAuthAccessResponse struct {
	AccessToken string `json:"access_token"`
}
