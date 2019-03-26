package rbac

import "sync"

type RBAC struct {
	sync.RWMutex
	policy  Policy
	manager RoleManager
}
