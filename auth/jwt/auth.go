// Thanks to https://github.com/adam-hanna/jwt-auth. This package is inspired by it.
// Package jwt provides JWT-based authentication function.
package jwt

import (
	"errors"
	Jwt "github.com/dgrijalva/jwt-go"
	"time"
)

type JWTAuth struct {
	option Options
	checker Checker
	revoker Revoker
}

// Checker will show if a token is revoked and return a uid that specifies a unique user.
// Id specifies a unique token and timestamp
type Checker func(id string, timestamp int64) (uid interface{}, valid bool)

// Revoker is used to revoke a token.
// Id specifies a unique token.
type Revoker func(id string) error

type Options struct {
	AccessPublicKey interface{}
	AccessPrivateKey interface{}
	AccessPrivateKeyLocation string
	AccessPublicKeyLocation string
	RefreshPublicKey interface{}
	RefreshPrivateKey interface{}
	RefreshPrivateKeyLocation string
	RefreshPublicKeyLocation string
	SigningMethod Jwt.SigningMethod
	AccessTokenDuration time.Duration
	RefreshTokenDuration time.Duration
	AccessHeader string
	RefreshHeader string
}

const (
	accessTokenDuration = time.Hour
	refreshTokenDuration = 7 * 24 * time.Hour
	accessHeader = "Authorization"
	refreshHeader = "Authorization"
)

var(
	ErrNoSigningMethod   	 =  errors.New("JWTAuth: no JWT signing method")
	ErrNoAccessHMACKey   	 =  errors.New("JWTAuth: you must provide a access HMAC Key")
	ErrNoRefreshHMACKey  	 =  errors.New("JWTAuth: you must provide a refresh HMAC Key")
	ErrNoAccessRSAKey    	 =  errors.New("JWTAuth: you must provide a access RSA Key")
	ErrNoRefreshRSAKey   	 =  errors.New("JWTAuth: you must provide a refresh RSA Key")
	ErrNoAccessECKey     	 =  errors.New("JWTAuth: you must provide a access EC Key")
	ErrNoRefreshECKey    	 =  errors.New("JWTAuth: you must provide a refresh EC Key")
	ErrInvalidSigningMethod  =  errors.New("JWTAuth: invalid JWT signing method")
	ErrTokenRevoked      	 =  errors.New("JWTAuth: access token has been revoked")
)

func NewJWTAuth(o Options, checker Checker, revoker Revoker) (*JWTAuth, error) {
	if o.SigningMethod == nil{
		return nil, ErrNoSigningMethod
	}

	switch o.SigningMethod {
	case Jwt.SigningMethodHS256, Jwt.SigningMethodHS384, Jwt.SigningMethodHS512:
		if o.AccessPublicKey == nil{
			return nil, ErrNoAccessHMACKey
		}
		o.AccessPrivateKey = o.AccessPublicKey

		if o.RefreshPublicKey == nil{
			return nil, ErrNoRefreshHMACKey
		}
		o.RefreshPrivateKey = o.RefreshPublicKey

	case Jwt.SigningMethodRS256, Jwt.SigningMethodRS384, Jwt.SigningMethodRS512:
		if o.AccessPublicKeyLocation == "" || o.AccessPrivateKeyLocation == ""{
			return nil, ErrNoAccessRSAKey
		}
		var err error
		o.AccessPrivateKey, o.AccessPublicKey, err = getRSAKeys(o.AccessPrivateKeyLocation, o.AccessPublicKeyLocation)
		if err != nil{
			return nil, err
		}

		if o.RefreshPublicKeyLocation == "" || o.RefreshPrivateKeyLocation == ""{
			return nil, ErrNoRefreshRSAKey
		}
		o.RefreshPrivateKey, o.RefreshPublicKey, err = getRSAKeys(o.RefreshPrivateKeyLocation, o.RefreshPublicKeyLocation)
		if err != nil{
			return nil, err
		}

	case Jwt.SigningMethodES256, Jwt.SigningMethodES384, Jwt.SigningMethodES512:
		if o.AccessPublicKeyLocation == "" || o.AccessPrivateKeyLocation == ""{
			return nil, ErrNoAccessECKey
		}

		var err error
		o.AccessPrivateKey, o.AccessPublicKey, err = getECKeys(o.AccessPrivateKeyLocation, o.AccessPublicKeyLocation)
		if err != nil{
			return nil, err
		}

		if o.RefreshPublicKeyLocation == "" || o.RefreshPrivateKeyLocation == ""{
			return nil, ErrNoRefreshECKey
		}
		o.RefreshPrivateKey, o.RefreshPublicKey, err = getECKeys(o.RefreshPrivateKeyLocation, o.RefreshPublicKeyLocation)
		if err != nil{
			return nil, err
		}

	default:
		return nil, ErrInvalidSigningMethod
	}

	if o.AccessTokenDuration <= 0 {
		o.AccessTokenDuration = accessTokenDuration
	}
	if o.RefreshTokenDuration <= 0{
		o.RefreshTokenDuration = refreshTokenDuration
	}
	if o.AccessHeader == ""{
		o.AccessHeader = accessHeader
	}
	if o.RefreshHeader == ""{
		o.RefreshHeader = refreshHeader
	}
	return &JWTAuth{option: o, checker: checker, revoker: revoker}, nil
}

func (a *JWTAuth) CreateAccessToken(id string) (string, error) {
	return generateJWT(id, a.option.AccessTokenDuration, a.option.AccessPrivateKey, a.option.SigningMethod)
}

func (a *JWTAuth) CreateRefreshToken(id string) (string, error)  {
	return generateJWT(id, a.option.RefreshTokenDuration, a.option.RefreshPrivateKey, a.option.SigningMethod)
}

func (a *JWTAuth) ValidateAccessToken(token string) (string, int64, error) {
	return validateJWT(token, a.option.AccessPublicKey, a.option.SigningMethod)
}

func (a *JWTAuth) ValidateRefreshToken(token string) (string, int64, error) {
	return validateJWT(token, a.option.RefreshPublicKey, a.option.SigningMethod)
}

func (a *JWTAuth) AccessChecker(token string) (interface{}, error) {
	id, timestamp, err := a.ValidateAccessToken(token)
	if err != nil{
		return nil, err
	}

	uid, revoked := a.checker(id, timestamp)
	if revoked{
		return nil, ErrTokenRevoked
	}
	return uid, nil
}

func (a *JWTAuth) RefreshChecker(token string) (interface{}, error) {
	id, timestamp, err := a.ValidateRefreshToken(token)
	if err != nil{
		return nil, err
	}

	uid, revoked := a.checker(id, timestamp)
	if revoked{
		return nil, ErrTokenRevoked
	}
	return uid, nil
}

func (a *JWTAuth) Revoke(id string) error {
	return a.revoker(id)
}

func (a *JWTAuth) AccessRevoker(token string) error {
	id, err := a.AccessChecker(token)
	if err != nil{
		return err
	}
	if err = a.revoker(id.(string)); err != nil{
		return err
	}
	return nil
}