package rbac

type Role interface {
	ID() int64
	ParentID() int64
	IsParent(Role) bool
	IsChild(Role) bool
	Permissions
}

type StandardRole struct {
	Id   int64
	Name string
	Permissions
	ParentId int64
}

func (r *StandardRole) ID() int64 {
	return r.Id
}

func (r *StandardRole) ParentID() int64 {
	return r.ParentId
}

func (r *StandardRole) IsParent(role Role) bool {
	return r.Id == role.ParentID()
}

func (r *StandardRole) IsChild(role Role) bool {
	return r.ParentId == role.ID()
}
