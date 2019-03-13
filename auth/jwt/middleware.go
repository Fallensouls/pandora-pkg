package jwt

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

// Authenticator checks whether user is authenticated.
func(a *JWTAuth) Authenticator() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "GET" {
			return
		}
		auth := c.Request.Header.Get(a.option.AccessHeader)
		if auth == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		parts := strings.SplitN(auth, " ", 2)
		if parts[0] != "Bearer" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		token := parts[1]
		id, err := a.AccessChecker(token)
		if err != nil{
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("user_id", id)
	}
}
