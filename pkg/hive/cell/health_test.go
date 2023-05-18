package cell

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStatusProvider(t *testing.T) {
	assert := assert.New(t)
	sp := NewHealthStatus()
	reporter := sp.forModule("module000")
	reporter.OK("OK")
	reporter.Degraded("bad")
	reporter.Stopped("meh")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	assert.NoError(sp.Finish(ctx))
	assert.Equal(sp.Processed(), uint64(3))
	assert.Equal(StatusStopped, sp.Get("module000").Level)
}
