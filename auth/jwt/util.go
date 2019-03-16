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
	Data map[string]interface{} `json:"data,omitempty"`
}

type TokenInfo struct {
	Id       string
	IssuedAt int64
	Data     map[string]interface{}
}

var (
	ErrInvalidToken  = errors.New("JWT: invalid token")
	ErrGetTokenId    = errors.New("JWT: can not get id from token")
	ErrGetIssuedTime = errors.New("JWT: can not get issued time from token")
	ErrGetData       = errors.New("JWT: can not get data from token")
)

// generateJWT generates a Json Web Token.
// Here we use id to specifies a token and add data(whatever you need) to the token.
// Please do not add important information such as password to payload of JWT.
func (t *Token) generateJWT(id string, data map[string]interface{}) (token string, err error) {
	claim := JWTClaims{
		StandardClaims: Jwt.StandardClaims{
			ExpiresAt: time.Now().Add(t.options.TokenDuration).Unix(),
			Id:        id,
			IssuedAt:  time.Now().Unix(),
		},
		Data: data,
	}

	unsigned := Jwt.NewWithClaims(t.options.SigningMethod, claim)
	token, err = unsigned.SignedString(t.privateKey)
	return
}

// validateJWT validates whether a jwt is valid.
// If so, it returns information included in the token and nil.
func (t *Token) validateJWT(tokenString string) (*TokenInfo, error) {
	token, err := Jwt.Parse(tokenString, func(token *Jwt.Token) (interface{}, error) {
		// Don't forget to validation the alg is what you expect:
		if token.Method.Alg() != t.options.SigningMethod.Alg() {
			return nil, fmt.Errorf("JWT: unexpected signing method %v", token.Header["alg"])
		}
		return t.publicKey, nil
	})

	claims := token.Claims.(Jwt.MapClaims)
	if claims["jti"] == nil || claims["iat"] == nil || err != nil {
		return nil, ErrInvalidToken
	}

	id, ok := claims["jti"].(string)
	if !ok {
		return nil, ErrGetTokenId
	}

	iat, ok := claims["iat"].(float64)
	if !ok {
		return nil, ErrGetIssuedTime
	}

	if claims["data"] == nil {
		return &TokenInfo{Id: id, IssuedAt: int64(iat)}, nil
	}

	data, ok := claims["data"].(map[string]interface{})
	if !ok {
		return nil, ErrGetData
	}
	return &TokenInfo{Id: id, IssuedAt: int64(iat), Data: data}, nil
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
	if err != nil {
		return nil, nil, fmt.Errorf("JWT: failed to load a private key, %s", err)
	}

	publicKeyContent, err := ioutil.ReadFile(publicKeyLocation)
	if err != nil {
		return nil, nil, fmt.Errorf("JWT: failed to load a public key, %s", err)
	}
	return privateKeyContent, publicKeyContent, nil
}

func getRSAKeys(privateKeyLocation, publicKeyLocation string) (interface{}, interface{}, error) {
	privateKeyContent, publicKeyContent, err := getKeysContent(privateKeyLocation, publicKeyLocation)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := Jwt.ParseRSAPrivateKeyFromPEM(privateKeyContent)
	if err != nil {
		return nil, nil, fmt.Errorf("JWT: failed to genereate a private rsa key, %s", err)
	}

	publicKey, err := Jwt.ParseRSAPublicKeyFromPEM(publicKeyContent)
	if err != nil {
		return nil, nil, fmt.Errorf("JWT: failed to genereate a public rsa key, %s", err)
	}
	return privateKey, publicKey, nil
}

func getECKeys(privateKeyLocation, publicKeyLocation string) (interface{}, interface{}, error) {
	privateKeyContent, publicKeyContent, err := getKeysContent(privateKeyLocation, publicKeyLocation)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := Jwt.ParseECPrivateKeyFromPEM(privateKeyContent)
	if err != nil {
		return nil, nil, fmt.Errorf("JWT: failed to genereate a private ec key, %s", err)
	}

	publicKey, err := Jwt.ParseECPublicKeyFromPEM(publicKeyContent)
	if err != nil {
		return nil, nil, fmt.Errorf("JWT: failed to genereate a public ec key, %s", err)
	}
	return privateKey, publicKey, nil
}
