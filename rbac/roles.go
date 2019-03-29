package rbac

import (
	"sync"
)

type Roles struct {
	roles sync.Map
}

func NewRoles() *Roles {
	roles := Roles{}
	return &roles
}

func (r *Roles) SetRole(role Role) {
	r.roles.Store(role.ID(), role)
}

func (r *Roles) GetRole(id int64) Role {
	role, ok := r.roles.Load(id)
	if !ok {
		return nil
	}
	return role.(Role)
}

func (r *Roles) IsSuperior(superior, subordinate Role) bool {
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
