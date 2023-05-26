package errs

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/multierr"
)

func TestInto(t *testing.T) {
	assert := assert.New(t)
	var err error
	assert.False(Into(&err, nil))
	assert.NoError(err)
	assert.True(Into(&err, fmt.Errorf("1")))
	assert.Equal("1", multierr.Errors(err)[0].Error())
	assert.True(Into(&err, fmt.Errorf("2")))
	assert.Equal("2", multierr.Errors(err)[1].Error())
	assert.True(Into(nil, fmt.Errorf("2")))
}
