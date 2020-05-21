package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
)

// For HMAC signing method, the key can be any []byte. It is recommended to generate
// a key using crypto/rand or something equivalent. You need the same key for signing
// and validating.
var hmacSampleSecret []byte

func init() {
	// Load sample key data
	hmacSampleSecret = []byte("test_secret")
}

// Example creating, signing, and encoding a JWT token using the HMAC signing method
func NewHmac() {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	// 标准中注册的声明(建议但不强制使用)：
  //   iss: jwt签发者
  //   sub: jwt所面向的用户
  //   aud: 接收jwt的一方
  //   exp: jwt的过期时间，这个过期时间必须要大于签发时间
  //   nbf: 定义在什么时间之前，该jwt都是不可用的.
  //   iat: jwt的签发时间
  //   jti: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"foo": "bar",
		"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(hmacSampleSecret)

	fmt.Println(tokenString, err)
}

// Example parsing and validating a token using the HMAC signing method
func ParseHhmac() {
	// sample token string taken from the New example
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJuYmYiOjE0NDQ0Nzg0MDB9.98zDoVOPSq0oWBxW1fq-e-EttgGs2KhNYx3G6zq414A"

	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return hmacSampleSecret, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims["foo"], claims["nbf"])
	} else {
		fmt.Println(err)
	}
}

func main() {
	NewHmac()
	ParseHhmac()
}
