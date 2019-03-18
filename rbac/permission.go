package rbac

type PermissionModel struct {
	Id         int64
	Permission permission
}

type permission struct {
	URI       string
	Operation operation
}

func (p *PermissionModel) Add() {

}

func (p *PermissionModel) Get() {

}

func (p *PermissionModel) Delete() {

}
