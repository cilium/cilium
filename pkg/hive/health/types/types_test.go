package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestID(t *testing.T) {
	id := Identifier{
		Module:    []string{"a", "b", "c"},
		Component: []string{"x", "y"},
	}

	tok, isMode := id.At(0)
	assert.Equal(t, tok, "a")
	assert.True(t, isMode)

	tok, isMode = id.At(1)
	assert.Equal(t, tok, "b")
	assert.True(t, isMode)

	tok, isMode = id.At(2)
	assert.Equal(t, tok, "c")
	assert.True(t, isMode)

	tok, isMode = id.At(3)
	assert.Equal(t, tok, "x")
	assert.False(t, isMode)

	tok, isMode = id.At(4)
	assert.Equal(t, tok, "y")
	assert.False(t, isMode)

	tok, isMode = id.At(5)
	assert.Equal(t, tok, "")
}
