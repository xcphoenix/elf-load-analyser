package data

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestData(t *testing.T) {
	var idx int16 = 10
	var flags int16 = 99
	s := newStatus(idx, flags)

	assert.Equal(t, idx, s.idx())
	assert.Equal(t, flags, s.flags())
}

func TestIsValid(t *testing.T) {
	assert.Equal(t, true, !IsValid(InvalidStatus))
	assert.Equal(t, false, withFlag(InvalidStatus, successFlag))
}
