package jwt

import (
	Jwt "github.com/dgrijalva/jwt-go"
	"time"
)

type Options struct {
	PrivateKeyLocation string
	PublicKeyLocation  string
	HMACKey            []byte
	SigningMethod      Jwt.SigningMethod
	TokenDuration      time.Duration
	IsBearerToken      bool
	Header             string
}
