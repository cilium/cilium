package cell

import (
	"testing"
)

func TestStatusProvider(t *testing.T) {
	//assert := assert.New(t)
	sp := NewStatusProvider()
	reporter := sp.forModule("module000")
	reporter.OK("OK")
	reporter.Degraded("bad")
	reporter.Stopped("meh")
}
