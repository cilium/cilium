// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package trigger

import (
	"testing"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/lock"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type TriggerTestSuite struct{}

var _ = Suite(&TriggerTestSuite{})

func (s *TriggerTestSuite) TestNeedsDelay(c *C) {
	t := &Trigger{params: Parameters{}}

	needsDelay, _ := t.needsDelay()
	c.Assert(needsDelay, Equals, false)

	t.params.MinInterval = time.Second

	t.lastTrigger = time.Now().Add(time.Second * -2)
	needsDelay, _ = t.needsDelay()
	c.Assert(needsDelay, Equals, false)

	t.lastTrigger = time.Now().Add(time.Millisecond * -900)
	needsDelay, _ = t.needsDelay()
	c.Assert(needsDelay, Equals, true)
	time.Sleep(time.Millisecond * 200)
	needsDelay, _ = t.needsDelay()
	c.Assert(needsDelay, Equals, false)
}

// TestMinInterval ensures that the MinInterval parameter is being respected
func (s *TriggerTestSuite) TestMinInterval(c *C) {
	var (
		mutex     lock.Mutex
		triggered int
	)

	t, err := NewTrigger(Parameters{
		TriggerFunc: func(reasons []string) {
			mutex.Lock()
			triggered++
			mutex.Unlock()
		},
		MinInterval:   time.Millisecond * 500,
		sleepInterval: time.Millisecond,
	})
	c.Assert(err, IsNil)
	c.Assert(t, Not(IsNil))

	// Trigger multiple times and sleep in between to guarantee that the
	// background routine probed in the meantime
	for i := 0; i < 5; i++ {
		t.Trigger()
		time.Sleep(time.Millisecond * 20)
	}

	mutex.Lock()
	triggeredCopy := triggered
	mutex.Unlock()
	c.Assert(triggeredCopy, Equals, 1)

	t.Shutdown()
}

// TestLongTrigger tests that a trigger that takes a second is only invoked
// once even though triggers are occurring in the background
func (s *TriggerTestSuite) TestLongTrigger(c *C) {
	var (
		mutex     lock.Mutex
		triggered int
	)

	t, err := NewTrigger(Parameters{
		TriggerFunc: func(reasons []string) {
			mutex.Lock()
			triggered++
			mutex.Unlock()
			time.Sleep(time.Second)
		},
		sleepInterval: time.Millisecond,
	})
	c.Assert(err, IsNil)
	c.Assert(t, Not(IsNil))

	// Trigger multiple times and sleep in between to guarantee that the
	// background routine probed in the meantime
	for i := 0; i < 5; i++ {
		t.Trigger()
		time.Sleep(time.Millisecond * 20)
	}

	mutex.Lock()
	triggeredCopy := triggered
	mutex.Unlock()
	c.Assert(triggeredCopy, Equals, 1)

	t.Shutdown()
}

func (s *TriggerTestSuite) TestShutdownFunc(c *C) {
	done := make(chan struct{})
	t, err := NewTrigger(Parameters{
		TriggerFunc: func(reasons []string) {},
		ShutdownFunc: func() {
			close(done)
		},
	})
	c.Assert(err, IsNil)

	t.Trigger()
	select {
	case <-done:
		c.Errorf("shutdown func called unexpectedly")
	default:
	}

	t.Shutdown()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		c.Errorf("timed out while waiting for shutdown func")
	}
}
