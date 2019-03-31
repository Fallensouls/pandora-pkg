package rbac

import "sync"

type AccessControl struct {
	Policies
	Roles
}

type PolicyManager struct {
	mu       sync.RWMutex
	policies Policies
}

func NewAccessControl(policies Policies, roles Roles) *AccessControl {
	return &AccessControl{policies, roles}
}

func (p *PolicyManager) LoadPolicies(policies []StandardPolicy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.policies.LoadPolicies(policies)
}

func (p *PolicyManager) Require(uri string, op Operation) ([]int64, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.policies.Require(uri, op)
}

func (p *PolicyManager) Destroy() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.policies.Destroy()
}

func (p *PolicyManager) IsGranted(uri string, op Operation, role Role) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.policies.IsGranted(uri, op, role)
}
