package jwt

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

// Authenticator checks whether user is authenticated.
func (t *Token) Authenticator() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "GET" {
			return
		}
		token, err := t.GetToken(c.Request)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		userInfo, err := t.CheckToken(token)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
		c.Set("user_id", userInfo.Id)
		if userInfo.Info != nil {
			c.Set("user_info", userInfo.Info)
		}
	}
}
