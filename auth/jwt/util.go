package jwt

import (
	"errors"
	"fmt"
	Jwt "github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"time"
)

type JWTClaims struct {
	Jwt.StandardClaims
	Id string `json:"id"`
}

var(
	ErrInvalidToken  = errors.New("JWTAuth: invalid token")
	ErrGetTokenId    = errors.New("JWTAuth: can not get id from token")
	ErrGetIssuedTime = errors.New("JWTAuth: can not get issued time from token")
)

// generateJWT generates Json Web Token used for authentication.
// Here we use user's id as extra data.
// Please do not add important information such as password to payload of JWT.
func generateJWT(id string, duration time.Duration, key interface{}, method Jwt.SigningMethod) (token string, err error) {
	claim := JWTClaims{
		Id: id,
		StandardClaims: Jwt.StandardClaims{
			ExpiresAt: time.Now().Add(duration).Unix(),
			//Issuer:    Config.Issuer,
			IssuedAt:  time.Now().Unix(),
		},
	}

	unsigned := Jwt.NewWithClaims(method, claim)
	token, err = unsigned.SignedString(key)
	return
}

// validateJWT validates whether jwt is valid.
// If so, we still have to check if user really logged in before.
func validateJWT(tokenString string, key interface{}, method Jwt.SigningMethod) (string, int64, error) {
	token, err := Jwt.Parse(tokenString, func(token *Jwt.Token) (interface{}, error) {
		// Don't forget to validation the alg is what you expect:
		if token.Method.Alg() != method.Alg() {
			return nil, fmt.Errorf("JWTAuth: unexpected signing method %v", token.Header["alg"])
		}
		return key, nil
	})

	claims := token.Claims.(Jwt.MapClaims)
	if claims["id"] == nil || claims["iat"] == nil || err != nil {
		return "", 0, ErrInvalidToken
	}

	id, ok := claims["id"].(string)
	if !ok {
		return "", 0, ErrGetTokenId
	}

	iat, ok := claims["iat"].(float64)
	if !ok{
		return "", 0, ErrGetIssuedTime
	}
	return id, int64(iat), nil
}

func SetSigningMethod(method string) Jwt.SigningMethod {
	switch method {
	case "HS256":
		return Jwt.SigningMethodHS256
	case "HS384":
		return Jwt.SigningMethodHS384
	case "HS512":
		return Jwt.SigningMethodHS512
	case "RSA256":
		return Jwt.SigningMethodRS256
	case "RSA384":
		return Jwt.SigningMethodRS384
	case "RSA512":
		return Jwt.SigningMethodRS512
	case "ES256":
		return Jwt.SigningMethodES256
	case "ES384":
		return Jwt.SigningMethodES384
	case "ES512":
		return Jwt.SigningMethodES512
	default:
		return Jwt.SigningMethodHS256
	}
}

func getKeysContent(privateKeyLocation, publicKeyLocation string) ([]byte, []byte, error) {
	privateKeyContent, err := ioutil.ReadFile(privateKeyLocation)
	if err != nil{
		return nil, nil, fmt.Errorf("JWTAuth: failed to load a private key, %s", err)
	}

	publicKeyContent, err := ioutil.ReadFile(publicKeyLocation)
	if err != nil{
		return nil, nil, fmt.Errorf("JWTAuth: failed to load a public key, %s", err)
	}
	return privateKeyContent, publicKeyContent, nil
}

func getRSAKeys(privateKeyLocation, publicKeyLocation string) (interface{}, interface{}, error) {
	privateKeyContent, publicKeyContent, err := getKeysContent(privateKeyLocation, publicKeyLocation)
	if err != nil{
		return nil, nil, err
	}
	privateKey, err := Jwt.ParseRSAPrivateKeyFromPEM(privateKeyContent)
	if err != nil{
		return nil, nil, fmt.Errorf("JWTAuth: failed to genereate a private rsa key, %s", err)
	}

	publicKey, err := Jwt.ParseRSAPublicKeyFromPEM(publicKeyContent)
	if err != nil{
		return nil, nil, fmt.Errorf("JWTAuth: failed to genereate a public rsa key, %s", err)
	}
	return privateKey, publicKey, nil
}

func getECKeys(privateKeyLocation, publicKeyLocation string) (interface{}, interface{}, error) {
	privateKeyContent, publicKeyContent, err := getKeysContent(privateKeyLocation, publicKeyLocation)
	if err != nil{
		return nil, nil, err
	}
	privateKey, err := Jwt.ParseECPrivateKeyFromPEM(privateKeyContent)
	if err != nil{
		return nil, nil, fmt.Errorf("JWTAuth: failed to genereate a private ec key, %s", err)
	}

	publicKey, err := Jwt.ParseECPublicKeyFromPEM(publicKeyContent)
	if err != nil{
		return nil, nil, fmt.Errorf("JWTAuth: failed to genereate a public ec key, %s", err)
	}
	return privateKey, publicKey, nil
}