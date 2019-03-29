package rbac

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPolicyManager_LoadPolicies(t *testing.T) {
	policies := []StandardPolicy{
		{`/data/**`, []PermissionGroup{
			{CR, []int64{1, 2, 3}},
			{Read, []int64{9, 10}},
		}},
		{`/auth/user/*`, []PermissionGroup{
			{CRUD, []int64{5}},
		}},
	}

	ac := NewAccessControl()
	ac.LoadPolicies(policies)
}

func TestPolicyManager_RequireAuth(t *testing.T) {
	policies := []StandardPolicy{
		{`/data/**`, []PermissionGroup{
			{CR, []int64{1, 2, 3}},
			{Read, []int64{9, 10}},
		}},
		{`/auth/user/*`, []PermissionGroup{
			{CRUD, []int64{5}},
		}},
	}

	ac := NewAccessControl()
	ac.LoadPolicies(policies)

	assert := assert.New(t)
	roleID, required := ac.RequireAuth(`/data/image`, Read)
	assert.Equal([]int64{1, 2, 3, 9, 10}, roleID)
	assert.True(required)

	roleID, required = ac.RequireAuth(`/auth/user`, Read)
	assert.Empty(roleID)
	assert.False(required)

	roleID, required = ac.RequireAuth(`/auth/user/1`, Delete)
	assert.Equal([]int64{5}, roleID)
	assert.True(required)
}

func TestPolicyManager_IsGranted(t *testing.T) {
	policies := []StandardPolicy{
		{`/data/**`, []PermissionGroup{
			{CRUD, []int64{1}},
			{CR, []int64{2, 3}},
			{Read, []int64{5, 10}},
		}},
	}

	roles := []StandardRole{
		{1, `admin`, nil, 0},
		{2, `roleManager`, nil, 1},
		{3, `role1`, nil, 1},
		{5, `role2`, nil, 3},
		{7, `role3`, nil, 3},
		{10, `role4`, nil, 5},
	}

	ac := NewAccessControl()
	ac.LoadPolicies(policies)

	assert := assert.New(t)
	assert.True(ac.IsGranted(`/data`, Read, &roles[0]))
	assert.True(ac.IsGranted(`/data/image`, CRUD, &roles[0]))
	assert.False(ac.IsGranted(`/data/image`, Delete, &roles[2]))
	assert.False(ac.IsGranted(`/data/image`, Create, &roles[3]))
	assert.True(ac.IsGranted(`/data/image`, CR, &roles[2]))
	assert.True(ac.IsGranted(`/data/image`, Read, &roles[5]))
	assert.False(ac.IsGranted(`/data/image`, Create, &roles[4]))
	assert.False(ac.IsGranted(`/data/image`, Read, &roles[4]))
	assert.False(ac.IsGranted(`/data/image`, Update, &roles[5]))
}
