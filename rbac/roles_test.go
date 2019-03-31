package rbac

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRoleManager_GetRole(t *testing.T) {
	roles := []StandardRole{
		{1, `admin`, nil, 0},
		{2, `roleManager`, nil, 1},
		{3, `role1`, nil, 1},
		{5, `role2`, nil, 3},
		{7, `role3`, nil, 3},
		{10, `role4`, nil, 5},
	}
	manager := NewRoleManager()

	for i := range roles {
		manager.manager.Store(roles[i].ID(), &roles[i])
	}

	for _, stdRole := range roles {
		role := manager.GetRole(stdRole.ID())
		assert.Equal(t, &stdRole, role.(*StandardRole))
	}
	assert.Nil(t, manager.GetRole(0))
}

func TestRoleManager_SetRole(t *testing.T) {
	roles := []StandardRole{
		{1, `admin`, nil, 0},
		{2, `roleManager`, nil, 1},
		{3, `role1`, nil, 1},
		{5, `role2`, nil, 3},
		{7, `role3`, nil, 3},
		{10, `role4`, nil, 5},
	}
	manager := NewRoleManager()

	for i := range roles {
		manager.SetRole(&roles[i])
	}

	assert := assert.New(t)
	for _, role := range roles {
		newrole, ok := manager.manager.Load(role.ID())
		assert.True(ok)
		assert.Equal(role.Id, newrole.(Role).ID())
	}
}

func TestRoleManager_IsSuperior(t *testing.T) {
	roles := []StandardRole{
		{1, `admin`, nil, 0},
		{2, `roleManager`, nil, 1},
		{3, `role1`, nil, 1},
		{5, `role2`, nil, 3},
		{7, `role3`, nil, 3},
		{10, `role4`, nil, 5},
	}
	manager := NewRoleManager()

	for i := range roles {
		manager.manager.Store(roles[i].ID(), &roles[i])
	}

	assert := assert.New(t)
	assert.True(manager.IsSuperior(&roles[0], &roles[1]))
	assert.True(manager.IsSuperior(&roles[0], &roles[2]))
	assert.True(manager.IsSuperior(&roles[0], &roles[3]))
	assert.True(manager.IsSuperior(&roles[0], &roles[4]))
	assert.True(manager.IsSuperior(&roles[0], &roles[5]))

	assert.False(manager.IsSuperior(&roles[1], &roles[0]))
	assert.False(manager.IsSuperior(&roles[4], &roles[0]))

	assert.False(manager.IsSuperior(&roles[1], &roles[2]))
	assert.False(manager.IsSuperior(&roles[1], &roles[3]))
	assert.False(manager.IsSuperior(&roles[1], &roles[4]))
	assert.False(manager.IsSuperior(&roles[1], &roles[5]))

	assert.True(manager.IsSuperior(&roles[2], &roles[3]))
	assert.True(manager.IsSuperior(&roles[2], &roles[4]))
	assert.True(manager.IsSuperior(&roles[2], &roles[5]))

	assert.True(manager.IsSuperior(&roles[3], &roles[5]))
	assert.False(manager.IsSuperior(&roles[3], &roles[4]))

	assert.False(manager.IsSuperior(&roles[5], &roles[4]))
	assert.False(manager.IsSuperior(&roles[5], &roles[3]))
	assert.False(manager.IsSuperior(&roles[5], &roles[2]))
	assert.False(manager.IsSuperior(&roles[5], &roles[1]))
	assert.False(manager.IsSuperior(&roles[5], &roles[0]))
}
