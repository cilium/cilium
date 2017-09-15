package runtime

import (
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
)

func TestFileImplementsIOReader(t *testing.T) {
	var file interface{} = File{}
	expected := "that File implements io.Reader"
	_, ok := file.(io.Reader)
	assert.True(t, ok, expected)
}
