package helper

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsNil(t *testing.T) {
	var a interface{} = (*int)(nil)
	assert.Equal(t, true, IsNil(nil))
	assert.Equal(t, true, a != nil)
	assert.Equal(t, true, IsNil(a))
}
