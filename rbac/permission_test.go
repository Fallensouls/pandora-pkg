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

	assert.Equal(true, permission1.Match(`/data/image`))
	assert.Equal(false, permission1.Match(`/data/image/1`))
	assert.Equal(true, permission2.Match(`/data/image`))
	assert.Equal(true, permission2.Match(`/data/image/1`))
	assert.Equal(true, permission2.Match(`/data/image/list/1`))
	assert.Equal(false, permission3.Match(`/data/image`))
	assert.Equal(false, permission3.Match(`/data/image/1`))

}

func TestStandardPermission_Include(t *testing.T) {
	permission1 := StandardPermission{`/data/*`, CRU}

	assert := assert.New(t)

	assert.Equal(true, permission1.Include(CR))
	assert.Equal(true, permission1.Include(CRU))
	assert.Equal(true, permission1.Include(Read))
	assert.Equal(true, permission1.Include(Create))
	assert.Equal(true, permission1.Include(Update))
	assert.Equal(false, permission1.Include(Delete))
}
