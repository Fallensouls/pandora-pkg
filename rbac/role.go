package rbac

type Role struct {
	Id          int64
	Permissions map[permission]bool
	ParentId    int64
}

func (r *Role) Add() {

}

func (r *Role) Get() {

}

func (r *Role) Update() {

}

func (r *Role) Delete() {

}

func (r *Role) HasPermission(p permission) bool {
	_, ok := r.Permissions[p]
	return ok
}

func (r *Role) IsParent(role Role) bool {
	return r.Id == role.ParentId
}

func (r *Role) IsChild(role Role) bool {
	return r.ParentId == role.Id
}
