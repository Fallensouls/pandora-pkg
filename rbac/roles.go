package rbac

import (
	"sync"
)

type Roles interface {
	SetRole(Role)
	GetRole(int64) Role
	IsSuperior(superior, subordinate Role) bool
}

type RoleManager struct {
	manager sync.Map
}

func NewRoleManager() *RoleManager {
	var manager RoleManager
	return &manager
}

func (r *RoleManager) SetRole(role Role) {
	r.manager.Store(role.ID(), role)
}

func (r *RoleManager) GetRole(id int64) Role {
	role, ok := r.manager.Load(id)
	if !ok {
		return nil
	}
	return role.(Role)
}

func (r *RoleManager) IsSuperior(superior, subordinate Role) bool {
	parent := subordinate
	for {
		if parent = r.GetRole(parent.ParentID()); parent == nil {
			return false
		}
		if parent.ID() == superior.ID() {
			return true
		}
	}
}
