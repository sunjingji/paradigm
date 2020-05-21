package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

type OAuthCredentialResponse struct {
	ClientId     string `json:"CLIENT_ID"`
	ClientSecret string `json:"CLIENT_SECRET"`
}

type OAuthAccessResponse struct {
	AccessToken string `json:"access_token"`
}

// 获取ClientId和秘钥
func GetCredential() (clientId string, clientSecret string, err error) {
	// Build url
	reqURL := fmt.Sprintf("http://localhost:9096/oauth/credential")
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stdout, "could not create HTTP request: %v", err)
		return
	}

	// Send request
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stdout, "could not send HTTP request: %v", err)
		return
	}
	defer resp.Body.Close()

	// Parse the request body into the `OAuthCredentialResponse` struct
	body, err := ioutil.ReadAll(resp.Body)
	var c OAuthCredentialResponse
	if err = json.Unmarshal(body, &c); err != nil {
		fmt.Fprintf(os.Stdout, "could not parse json response: %v", err)
		return
	}

	return c.ClientId, c.ClientSecret, nil
}

// 使用code换取access_token
func GetAccessToken(clientId string, clientSecret string, code string) (token string, errCode int) {
	// Lets for the HTTP request to call the GitHub OAuth endpoint to get our access token
	reqURL := fmt.Sprintf("http://localhost:9096/oauth/access_token?client_id=%s&client_secret=%s&grant_type=authorization_code&code=%s&redirect_uri=http://localhost:9094/redirect", clientId, clientSecret, code)
	req, err := http.NewRequest(http.MethodPost, reqURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stdout, "could not create HTTP request: %v", err)
		errCode = http.StatusBadRequest
		return
	}

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

func main() {
	// Get credential
	clientId, clientSecret, err := GetCredential()
	if err != nil {
		fmt.Fprintf(os.Stdout, "get credetial failed, %v", err)
		return
	}

	// Service /hello
	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		redirectUrl := fmt.Sprintf("http://localhost:9096/oauth/authorize?response_type=code&client_id=%s&redirect_uri=http://localhost:9094/redirect", clientId)
		w.Header().Set("Location", redirectUrl)
		w.WriteHeader(http.StatusFound)
	})

	// Create a new redirect route
	http.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		// First, we need to get the value of the `code` query param
		err := r.ParseForm()
		if err != nil {
			fmt.Fprintf(os.Stdout, "could not parse query: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")

		// Second, get access token
		token, errCode := GetAccessToken(clientId, clientSecret, code)
		if errCode != http.StatusOK {
			w.WriteHeader(errCode)
			return
		}

		// Finally, redirect user to "http://localhost:9096/resource"
		redirectUrl := fmt.Sprintf("http://localhost:9096/resource?access_token=%s", token)
		w.Header().Set("Location", redirectUrl)
		w.WriteHeader(http.StatusFound)
	})

	http.ListenAndServe(":9094", nil)
}
