package rbac

import "github.com/gin-gonic/gin"

func (ac *AccessControl) Authorizer() gin.HandlerFunc {
	return func(c *gin.Context) {
		var operation Operation
		switch c.Request.Method {
		case "GET":
			operation = Read
		case "POST":
			operation = Create
		case "PUT":
			operation = Update
		case "DELETE":
			operation = Delete
		default:
			return
		}
		roleID, required := ac.RequireAuth(c.Request.URL.Path, operation)
		c.Set("role_id", roleID)
		c.Set("need_auth", required)
	}
}
