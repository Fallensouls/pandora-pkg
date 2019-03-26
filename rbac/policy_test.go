package rbac

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewPolicyTree(t *testing.T) {
	root := NewPolicyTree()

	assert := assert.New(t)
	assert.Equal(``, root.path)
	assert.Empty(root.children)
	assert.Empty(root.groups)
}

func TestPolicyTree_Load(t *testing.T) {
	policies := []StandardPolicy{
		{`/data/**`, []PermissionGroup{
			{CR, []int64{1, 2, 3}},
		}},
		{`/data`, []PermissionGroup{
			{CRUD, []int64{4, 7}},
		}},
		{`/auth/`, []PermissionGroup{
			{Read, []int64{2, 4, 5}},
		}},
		{`/auth/user/*`, []PermissionGroup{
			{CRUD, []int64{5}},
		}},
	}

	tree := NewPolicyTree()
	tree.Load(policies)

	assert := assert.New(t)
	assert.Equal(2, len(tree.children))

	data := tree.children[0]
	assert.Equal(`data`, data.path)
	assert.Equal(CRUD, data.groups[0].Operation)
	assert.Equal([]int64{4, 7}, data.groups[0].RoleID)
	assert.Equal(1, len(data.children))
	assert.Equal(`**`, data.children[0].path)
	assert.Equal(CR, data.children[0].groups[0].Operation)
	assert.Equal([]int64{1, 2, 3}, data.children[0].groups[0].RoleID)

	auth := tree.children[1]
	assert.Equal(`auth`, auth.path)
	assert.Equal(Read, auth.groups[0].Operation)
	assert.Equal(1, len(auth.children))
	assert.Equal([]int64{2, 4, 5}, auth.groups[0].RoleID)

	user := auth.children[0]
	assert.Equal(`user`, user.path)
	assert.Equal(1, len(user.children))
	assert.Empty(user.groups)

	assert.Equal(`*`, user.children[0].path)
	assert.Equal(CRUD, user.children[0].groups[0].Operation)
	assert.Equal([]int64{5}, user.children[0].groups[0].RoleID)
	assert.Empty(user.children[0].children)
}

func TestPolicyTree_Require(t *testing.T) {
	policies := []StandardPolicy{
		{`/data/**`, []PermissionGroup{
			{CR, []int64{1, 2, 3}},
			{Read, []int64{9, 10}},
		}},
		{`/auth/user/*`, []PermissionGroup{
			{CRUD, []int64{5}},
		}},
	}

	tree := NewPolicyTree()
	tree.Load(policies)

	assert := assert.New(t)
	roleID, required := tree.Require(`/data/image`, Read)
	assert.Equal([]int64{1, 2, 3, 9, 10}, roleID)
	assert.True(required)

	roleID, required = tree.Require(`/auth/user`, Read)
	assert.Empty(roleID)
	assert.False(required)

	roleID, required = tree.Require(`/auth/user/1`, Delete)
	assert.Equal([]int64{5}, roleID)
	assert.True(required)
}

func TestPolicyTree_Destroy(t *testing.T) {
	policies := []StandardPolicy{
		{`/data/**`, []PermissionGroup{
			{CR, []int64{1, 2, 3}},
		}},
		{`/data`, []PermissionGroup{
			{CRUD, []int64{4, 7}},
		}},
		{`/auth/`, []PermissionGroup{
			{Read, []int64{2, 4, 5}},
		}},
		{`/auth/user/*`, []PermissionGroup{
			{CRUD, []int64{5}},
		}},
	}

	tree := NewPolicyTree()
	tree.Load(policies)
	tree.Destroy()

	assert.Empty(t, tree)
}
