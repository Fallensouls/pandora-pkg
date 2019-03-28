package rbac

import "sync"

type AccessControl struct {
	PolicyManager
	roleManager Roles
}

type PolicyManager struct {
	sync.RWMutex
	policyManager Policies
}

func (p *PolicyManager) LoadPolicies(policies []StandardPolicy) {
	p.Lock()
	defer p.Unlock()
	p.policyManager.Load(policies)
}

func (p *PolicyManager) RequireAuth(uri string, op Operation) ([]int64, bool) {
	p.RLock()
	defer p.RUnlock()
	return p.policyManager.Require(uri, op)
}

func (p *PolicyManager) IsGranted(uri string, op Operation, role Role) bool {
	p.RLock()
	defer p.RUnlock()
	roleID, required := p.policyManager.Require(uri, op)
	if !required {
		return true
	}
	for _, id := range roleID {
		if role.ID() == id {
			return true
		}
	}
	return false
}

func (ac *AccessControl) AddRole(role Role) {
	ac.roleManager.SetRole(role)
}

func (ac *AccessControl) GetRole(id int64) Role {
	return ac.roleManager.GetRole(id)
}
