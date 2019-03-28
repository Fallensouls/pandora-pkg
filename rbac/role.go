package rbac

type Role interface {
	// ID should return thd id of a role.
	ID() int64

	// ParentID should return the id of a role's parent.
	ParentID() int64

	// IsParent shows whether the role is a parent of another role.
	IsParent(Role) bool

	// IsChild shows whether the role is a child of another role.
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
