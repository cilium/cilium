// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cleanup

import (
	"sync"
	"testing"

	. "github.com/cilium/checkmate"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type CleanupTestSuite struct{}

var _ = Suite(&CleanupTestSuite{})

func (cts *CleanupTestSuite) TestHandleCleanup(c *C) {
	wg := &sync.WaitGroup{}
	ch := make(chan struct{})
	i := 0
	DeferTerminationCleanupFunction(wg, ch, func() {
		i++
	})
	close(ch)
	wg.Wait()
	c.Assert(i, Equals, 1)
}
