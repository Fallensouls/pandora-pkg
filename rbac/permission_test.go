package rbac

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStandardPermission_Match(t *testing.T) {
	permission1 := StandardPermission{`/data/*`, CRU}
	permission2 := StandardPermission{`/data/**`, CR}
	permission3 := StandardPermission{`/data`, CRUD}

	assert := assert.New(t)

	assert.True(permission1.Match(`/data/image`))
	assert.False(permission1.Match(`/data/image/1`))
	assert.True(permission2.Match(`/data/image`))
	assert.True(permission2.Match(`/data/image/1`))
	assert.True(permission2.Match(`/data/image/list/1`))
	assert.False(permission3.Match(`/data/image`))
	assert.False(permission3.Match(`/data/image/1`))
	assert.False(permission1.Match(`/auth`))
	assert.False(permission2.Match(`/`))
	assert.False(permission3.Match(`/**`))
}

func TestStandardPermission_Include(t *testing.T) {
	permission1 := StandardPermission{`/data/*`, CRU}

	assert := assert.New(t)

	assert.True(permission1.Include(CR))
	assert.True(permission1.Include(CRU))
	assert.True(permission1.Include(Read))
	assert.True(permission1.Include(Create))
	assert.True(permission1.Include(Update))
	assert.False(permission1.Include(Delete))
}

func TestNewPermissionList(t *testing.T) {
	permissions := []StandardPermission{
		{`/data/*`, CRU},
		{`/data/**`, CR},
		{`/data`, CRUD},
	}

	list := NewPermissionList()
	list.Load(permissions)
	assert := assert.New(t)
	assert.True(list.HasPermission(`/data/*`, CRU))
	assert.True(list.HasPermission(`/data/**`, CR))
	assert.True(list.HasPermission(`/data`, CRUD))
}

//func TestPermissionList_Add(t *testing.T) {
//	list := make(PermissionList, 0)
//	list.add(`/data/*`, CRU)
//
//	assert.True(t, list.HasPermission(`/data/*`, CRU))
//}

func TestPermissionList_HasPermission(t *testing.T) {
	list := make(PermissionList, 0)

	permissions := []StandardPermission{
		{`/data/*`, CRU},
		{`/data/**`, CR},
		{`/data`, CRUD},
	}
	list = append(list, permissions...)

	assert := assert.New(t)
	assert.True(list.HasPermission(`/data/image`, CRU))
	assert.True(list.HasPermission(`/data/image`, CR))
	assert.False(list.HasPermission(`/data/image`, Delete))
	assert.False(list.HasPermission(`/data/image/1`, CRU))
	assert.False(list.HasPermission(`/auth/`, CRU))
	assert.False(list.HasPermission(`/`, CRU))
	assert.True(list.HasPermission(`/data/image/1`, CR))
	assert.True(list.HasPermission(`/data/image`, CR))
	assert.False(list.HasPermission(`/data/image/1`, Update))
	assert.False(list.HasPermission(`/auth/image/1`, CR))
	assert.True(list.HasPermission(`/data`, CRUD))
	assert.True(list.HasPermission(`/data`, Create))
	assert.True(list.HasPermission(`/data`, RUD))
	assert.False(list.HasPermission(`/data/image`, CRUD))
	assert.False(list.HasPermission(`/auth`, CRUD))
}

func TestPermissionList_Destroy(t *testing.T) {
	list := make(PermissionList, 0)

	permissions := []StandardPermission{
		{`/data/*`, CRU},
		{`/data/**`, CR},
		{`/data`, CRUD},
	}
	list = append(list, permissions...)

	list.Destroy()
	assert.Empty(t, list)
}

func TestNewTree(t *testing.T) {
	permissions := PermissionList{
		{`/data/*`, CRU},
		{`/data/**`, CR},
		{`/data`, CRUD},
		{`/auth/`, Read},
		{`/auth/user/*`, CRUD},
	}

	tree := NewPermissionTree()
	tree.Load(permissions)

	assert := assert.New(t)
	assert.Equal(2, len(tree.children))
	assert.Equal(`data`, tree.children[0].path)
	assert.Equal(CRUD, tree.children[0].operation)
	assert.Equal(`auth`, tree.children[1].path)
	assert.Equal(Read, tree.children[1].operation)

	assert.Equal(2, len(tree.children[0].children))
	assert.Equal(`*`, tree.children[0].children[0].path)
	assert.Equal(CRU, tree.children[0].children[0].operation)
	assert.Equal(`**`, tree.children[0].children[1].path)
	assert.Equal(CR, tree.children[0].children[1].operation)

	assert.Equal(1, len(tree.children[1].children))
	assert.Equal(`user`, tree.children[1].children[0].path)
	assert.Equal(Nil, tree.children[1].children[0].operation)

	assert.Equal(1, len(tree.children[1].children[0].children))
	assert.Equal(`*`, tree.children[1].children[0].children[0].path)
	assert.Equal(CRUD, tree.children[1].children[0].children[0].operation)
}

func TestPermissionTree_Match(t *testing.T) {
	permissions := PermissionList{
		{`/data/**`, CR},
		{`/data`, CRUD},
		{`/auth/`, Read},
		{`/auth/user/*`, CRUD},
	}

	tree := NewPermissionTree()
	tree.Load(permissions)

	assert := assert.New(t)
	assert.True(tree.Match(`/data`))
	assert.True(tree.Match(`/data/image`))
	assert.True(tree.Match(`/data/image/1`))
	assert.True(tree.Match(`/auth`))
	assert.True(tree.Match(`/auth/user`))
	assert.True(tree.Match(`/auth/user/1`))
	assert.False(tree.Match(`/auth/user/vip/1`))
	assert.False(tree.Match(`/`))
	assert.False(tree.Match(`/login`))
}

func TestPermissionTree_HasPermission(t *testing.T) {
	permissions := PermissionList{
		{`/data/*`, CRU},
		{`/data/**`, CR},
		{`/data`, CRUD},
		{`/auth/`, Read},
		{`/auth/user/*`, CRUD},
	}

	tree := NewPermissionTree()
	tree.Load(permissions)
	assert := assert.New(t)

	assert.True(tree.HasPermission(`/data/image`, CRU))
	assert.True(tree.HasPermission(`/data/image`, CR))
	assert.False(tree.HasPermission(`/data/image`, Delete))
	assert.False(tree.HasPermission(`/data/image/1`, CRU))
	assert.False(tree.HasPermission(`/auth/`, CRU))
	assert.False(tree.HasPermission(`/`, CRU))
	assert.True(tree.HasPermission(`/data/image/1`, CR))
	assert.True(tree.HasPermission(`/data/image`, CR))
	assert.False(tree.HasPermission(`/data/image/1`, Update))
	assert.False(tree.HasPermission(`/auth/image/1`, CR))
	assert.True(tree.HasPermission(`/data`, CRUD))
	assert.True(tree.HasPermission(`/data`, Create))
	assert.True(tree.HasPermission(`/data`, RUD))
	assert.False(tree.HasPermission(`/data/image`, CRUD))

	assert.False(tree.HasPermission(`/auth`, CRUD))
	assert.False(tree.HasPermission(`/auth/user`, Read))
	assert.True(tree.HasPermission(`/auth/user/1`, CRU))
	assert.False(tree.HasPermission(`/auth/user/vip/1`, Read))
}

func TestPermissionTree_Destroy(t *testing.T) {
	permissions := PermissionList{
		{`/data/*`, CRU},
		{`/data/**`, CR},
		{`/data`, CRUD},
		{`/auth/`, Read},
		{`/auth/user/*`, CRUD},
	}

	tree := NewPermissionTree()
	tree.Load(permissions)
	tree.Destroy()
	assert := assert.New(t)
	assert.Empty(tree)
}
