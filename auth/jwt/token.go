// Thanks to https://github.com/adam-hanna/jwt-auth. This package is inspired by it.
// Package jwt provides JWT-based authentication function.
package jwt

import (
	"errors"
	Jwt "github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
)

type Token struct {
	privateKey interface{}
	publicKey  interface{}
	options    Options
	store      Store
}

var (
	ErrNoSigningMethod      = errors.New("JWT: no JWT signing method")
	ErrNoHMACKey            = errors.New("JWT: you must provide a HMAC Key")
	ErrNoRSAKey             = errors.New("JWT: you must provide a RSA Key")
	ErrNoECKey              = errors.New("JWT: you must provide a EC Key")
	ErrInvalidSigningMethod = errors.New("JWT: invalid JWT signing method")
	ErrInvalidDuration      = errors.New("JWT: duration of jwt can not be less than or equal to zero")
	ErrTokenNotFound        = errors.New("JWT: there is no token in the given header")
	ErrNoHeader             = errors.New("JWT: there is no specified header which contains a token")
	//ErrTokenRevoked      	 =  errors.New("JWT: your token has been revoked")
)

func NewTokenConfig(options Options, store Store) (*Token, error) {
	if options.SigningMethod == nil {
		return nil, ErrNoSigningMethod
	}

	var (
		privateKey interface{}
		publicKey  interface{}
	)

	switch options.SigningMethod {
	case Jwt.SigningMethodHS256, Jwt.SigningMethodHS384, Jwt.SigningMethodHS512:
		if options.HMACKey == nil {
			return nil, ErrNoHMACKey
		}
		privateKey = options.HMACKey
		publicKey = options.HMACKey

	case Jwt.SigningMethodRS256, Jwt.SigningMethodRS384, Jwt.SigningMethodRS512:
		if options.PublicKeyLocation == "" || options.PrivateKeyLocation == "" {
			return nil, ErrNoRSAKey
		}
		var err error
		privateKey, publicKey, err = getRSAKeys(options.PrivateKeyLocation, options.PublicKeyLocation)
		if err != nil {
			return nil, err
		}

	case Jwt.SigningMethodES256, Jwt.SigningMethodES384, Jwt.SigningMethodES512:
		if options.PublicKeyLocation == "" || options.PrivateKeyLocation == "" {
			return nil, ErrNoECKey
		}
		var err error
		privateKey, publicKey, err = getECKeys(options.PrivateKeyLocation, options.PublicKeyLocation)
		if err != nil {
			return nil, err
		}

	default:
		return nil, ErrInvalidSigningMethod
	}

	if options.TokenDuration <= 0 {
		return nil, ErrInvalidDuration
	}

	if options.Header == "" {
		return nil, ErrNoHeader
	}

	return &Token{privateKey, publicKey, options, store}, nil
}

func (t *Token) GetToken(r *http.Request) (string, error) {
	header := r.Header.Get(t.options.Header)
	if header == "" {
		return "", ErrTokenNotFound
	}
	if t.options.IsBearerToken {
		token := header[7:]
		return token, nil
	}
	return header, nil
}

func (t *Token) GenerateToken(id string, data map[string]interface{}) (string, error) {
	return t.generateJWT(id, data)
}

func (t *Token) ValidateToken(token string) (*TokenInfo, error) {
	return t.validateJWT(token)
}

func (t *Token) GetTokenData(token string) (map[string]interface{}, error) {
	tokenInfo, err := t.validateJWT(token)
	return tokenInfo.Data, err
}

func (t *Token) CheckToken(token string) (*UserInfo, error) {
	tokenInfo, err := t.validateJWT(token)
	if err != nil {
		return nil, err
	}
	// When there is no storage, we would like to return information from token as UserInfo.
	if t.store == nil {
		return &UserInfo{tokenInfo.Id, tokenInfo.Data}, nil
	}
	return t.store.Check(tokenInfo.Id, tokenInfo.IssuedAt)
}

func (t *Token) RevokeToken(id string) error {
	// When there is no storage, no token would be revoked.
	if t.store == nil {
		log.Panicf("JWT: no storage provided, please check your storage setting")
	}
	return t.store.Revoke(id)
}
