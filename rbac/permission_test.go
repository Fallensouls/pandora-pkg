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

func TestNewList(t *testing.T) {
	permissions := map[string]operation{
		`/data/*`:  CRU,
		`/data/**`: CR,
		`/data`:    CRUD,
	}

	list := NewList(permissions)
	assert := assert.New(t)
	assert.True(list.HasPermission(`/data/*`, CRU))
	assert.True(list.HasPermission(`/data/**`, CR))
	assert.True(list.HasPermission(`/data`, CRUD))
}

func TestPermissionList_Add(t *testing.T) {
	list := make(PermissionList, 0)
	list.Add(`/data/*`, CRU)

	assert.True(t, list.HasPermission(`/data/*`, CRU))
}

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

	tree := NewTree(permissions)

	assert := assert.New(t)
	assert.Equal(2, len(tree.Children))
	assert.Equal(`data`, tree.Children[0].Path)
	assert.Equal(CRUD, tree.Children[0].Operation)
	assert.Equal(`auth`, tree.Children[1].Path)
	assert.Equal(Read, tree.Children[1].Operation)

	assert.Equal(2, len(tree.Children[0].Children))
	assert.Equal(`*`, tree.Children[0].Children[0].Path)
	assert.Equal(CRU, tree.Children[0].Children[0].Operation)
	assert.Equal(`**`, tree.Children[0].Children[1].Path)
	assert.Equal(CR, tree.Children[0].Children[1].Operation)

	assert.Equal(1, len(tree.Children[1].Children))
	assert.Equal(`user`, tree.Children[1].Children[0].Path)
	assert.Equal(Nil, tree.Children[1].Children[0].Operation)

	assert.Equal(1, len(tree.Children[1].Children[0].Children))
	assert.Equal(`*`, tree.Children[1].Children[0].Children[0].Path)
	assert.Equal(CRUD, tree.Children[1].Children[0].Children[0].Operation)
}

func TestPermissionTree_Match(t *testing.T) {
	permissions := PermissionList{
		{`/data/**`, CR},
		{`/data`, CRUD},
		{`/auth/`, Read},
		{`/auth/user/*`, CRUD},
	}

	tree := NewTree(permissions)
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

	tree := NewTree(permissions)
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

	tree := NewTree(permissions)
	tree.Destroy()
	assert := assert.New(t)
	assert.Empty(tree)
}
