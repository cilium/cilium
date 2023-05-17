package cell

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStatusProvider(t *testing.T) {
	assert := assert.New(t)
	sp := NewStatusProvider()
	reporter := sp.forModule("module000")
	reporter.OK("OK")
	reporter.Degraded("bad")
	reporter.Stopped("meh")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	assert.NoError(sp.finish(ctx))
	assert.Equal(sp.processed.Load(), uint64(3))
	assert.Equal(sp.moduleStatuses["module000"].Level, StatusStopped)
}
