package jwt

type Store interface {
	// Check should check whether a token has been revoked.
	// If not, it will return some information of user and nil.
	Check(tokenId string, issuedAt int64) (info *UserInfo, err error)

	// Revoke should revoke a token which is no longer in use.
	// This case often happens when a user logs out
	// or an authorization ends.
	Revoke(tokenId string) error
}

type UserInfo struct {
	Id   string
	Info map[string]interface{}
}
