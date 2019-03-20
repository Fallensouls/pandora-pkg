package rbac

import "sync"

type RoleManager struct {
	Roles sync.Map
}

func (m *RoleManager) LoadRoles(roles []Role) {
	for _, role := range roles {
		m.Roles.Store(role.ID(), role)
	}
}

func (m *RoleManager) GetRole(id int64) *Role {
	role, ok := m.Roles.Load(id)
	if !ok {
		return nil
	}
	return role.(*Role)
}

func (m *RoleManager) IsSuperior(superior, subordinate Role) {

}
