package rbac

type Role interface {
	ID() int64
	ParentID() int64
	HasPermission(uri string, op operation) bool
	IsParent(Role) bool
	IsChild(Role) bool
}

type StandardRole struct {
	Id          int64
	Name        string
	Permissions Permissions
	ParentId    int64
}

func (r *StandardRole) ID() int64 {
	return r.Id
}

func (r *StandardRole) ParentID() int64 {
	return r.ParentId
}

func (r *StandardRole) HasPermission(uri string, op operation) (flag bool) {
	return r.Permissions.HasPermission(uri, op)
}

func (r *StandardRole) Destroy() {
	r.Permissions.Destroy()
}

func (r *StandardRole) IsParent(role Role) bool {
	return r.Id == role.ParentID()
}

func (r *StandardRole) IsChild(role Role) bool {
	return r.ParentId == role.ID()
}
