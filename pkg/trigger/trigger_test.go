// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package trigger

import (
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/lock"

	. "gopkg.in/check.v1"
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
