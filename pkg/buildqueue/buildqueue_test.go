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

package buildqueue

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

// BuildQueueTestSuite tests the build queue
//
// The tests are split into two main strategies to provide best coverage:
//
// 1) DETERMINISTIC: Tests that are as guided as possible to verify
//    correctness by putting the build queue through individual stages, e.g.
//    queue a regular build, queue exclusive, ensure regular does not interrupt
//    exclusive, ...
//
//      TestBuildQueue(c *C)
//      TestBuildStatus(c *C)
//      TestDrain(c *C)
//      TestExclusiveBuild(c *C)
//
// 2) BRUTE FORCE: This test enqueues a lot of parallel builds with semi random
//    build times while constantly checking for build guarantees. This test
//    will run differently in each run. The goal is to catch build guarantee
//    failures by means of brute force
//
//      TestBuildGuarantees(c *C)
//
type BuildQueueTestSuite struct{}

var _ = Suite(&BuildQueueTestSuite{})

type testBuilder struct {
	mutex         lock.Mutex
	uuid          string
	nbuilds       int
	building      bool
	finishBuild   chan error
	queued        int
	checkParallel *BuildQueue
	completeAfter time.Duration
}

func newTestBuilder(uuid string) *testBuilder {
	test := &testBuilder{
		uuid:        uuid,
		finishBuild: make(chan error, 1),
	}

	return test
}

func (t *testBuilder) GetUUID() string {
	return t.uuid
}

func (t *testBuilder) BuildQueued() {
	t.mutex.Lock()
	t.queued++
	fmt.Printf("%s: queued build, %d now queued\n", t.uuid, t.queued)
	t.mutex.Unlock()
}

func (t *testBuilder) BuildsDequeued(nbuilds int, cancelled bool) {
	t.mutex.Lock()
	t.queued -= nbuilds
	fmt.Printf("%s: dequeued %d builds cancelled=%t, %d now queued\n", t.uuid, nbuilds, cancelled, t.queued)
	t.mutex.Unlock()
}

func (t *testBuilder) Build() error {
	var err error

	t.mutex.Lock()
	fmt.Printf("%s: starting build...\n", t.uuid)
	t.building = true
	t.mutex.Unlock()

	if t.checkParallel != nil {
		err := t.checkParallel.checkBuildGuarantees()
		if err != nil {
			msg := fmt.Sprintf("Build guarantee violated: %s", err)
			panic(msg)
		}
	}

	if t.completeAfter != 0 {
		time.Sleep(t.completeAfter)
		fmt.Printf("%s: build finished after %s\n", t.uuid, t.completeAfter)
		err = nil
	} else {
		err = <-t.finishBuild
		fmt.Printf("%s: build finished success=%t\n", t.uuid, err == nil)
	}

	t.mutex.Lock()
	t.building = false
	t.nbuilds++
	t.mutex.Unlock()

	return err
}

func (t *testBuilder) getNumQueuedBuilds() int {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return t.queued
}

func (t *testBuilder) getNumBuilds() int {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return t.nbuilds
}

func (t *testBuilder) isBuilding() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return t.building
}

func (t *testBuilder) makeBuildReturn(err error) {
	t.finishBuild <- err
}

func (s *BuildQueueTestSuite) TestBuildQueue(c *C) {
	bq := NewBuildQueue("test")
	c.Assert(bq, Not(IsNil))
	defer bq.Stop()

	// create & enqueue builder1
	builder1 := newTestBuilder("builder1")
	c.Assert(builder1.getNumBuilds(), Equals, 0)
	bq.Enqueue(builder1)

	// create & enqueue builder2
	builder2 := newTestBuilder("builder2")
	c.Assert(builder2.getNumBuilds(), Equals, 0)
	bq.Enqueue(builder2)

	// Wait for builder1 to start building
	c.Assert(testutils.WaitUntil(func() bool {
		return builder1.isBuilding()
	}, 2*time.Second), IsNil)

	// Since builder1 started, no build should be queued
	c.Assert(builder1.getNumQueuedBuilds(), Equals, 0)

	// Wait for builder2 to start building
	c.Assert(testutils.WaitUntil(func() bool {
		return builder2.isBuilding()
	}, 2*time.Second), IsNil)

	// Since builder2 started, no build should be queued
	c.Assert(builder2.getNumQueuedBuilds(), Equals, 0)

	// Enqueue a 2nd build of builder1
	bq.Enqueue(builder1)
	c.Assert(builder1.getNumQueuedBuilds(), Equals, 1)

	// Let the first build of builder1 complete
	builder1.makeBuildReturn(nil)

	// Wait for first build of builder1 to complete
	c.Assert(testutils.WaitUntil(func() bool {
		return builder1.getNumBuilds() == 1
	}, 2*time.Second), IsNil)

	// Wait for the 2nd build of builder1 to start
	c.Assert(testutils.WaitUntil(func() bool {
		return builder1.isBuilding()
	}, 2*time.Second), IsNil)

	// The 2nd build should have started and thus no build should be queued
	c.Assert(builder1.getNumQueuedBuilds(), Equals, 0)

	// Check that the 2nd build of builder1 did not complete. Give it 100 millisecond
	c.Assert(testutils.WaitUntil(func() bool {
		return builder1.getNumBuilds() == 2
	}, 100*time.Millisecond), Not(IsNil))

	// Let the build 2 of builder1 complete
	builder1.makeBuildReturn(nil)
	c.Assert(builder1.getNumQueuedBuilds(), Equals, 0)

	// Build 2 of builder1 should complete
	c.Assert(testutils.WaitUntil(func() bool {
		return builder1.getNumBuilds() == 2
	}, 2*time.Second), IsNil)
	c.Assert(builder1.getNumQueuedBuilds(), Equals, 0)

	// Let the first build of builder 2 complete
	builder2.makeBuildReturn(nil)

	// Out of the two builds of builder 2, only one should have been
	// performed
	c.Assert(testutils.WaitUntil(func() bool {
		return builder2.getNumBuilds() == 1
	}, 2*time.Second), IsNil)
}

func (s *BuildQueueTestSuite) TestBuildStatus(c *C) {
	bq := NewBuildQueue("test")
	c.Assert(bq, Not(IsNil))
	defer bq.Stop()

	// create builder1
	builder1 := newTestBuilder("builder1")

	// enqueue builder1
	buildStatus := bq.Enqueue(builder1)

	// Let the build fail with a failure
	builder1.makeBuildReturn(fmt.Errorf("build error"))

	buildSuccessful := <-buildStatus
	c.Assert(buildSuccessful, Equals, false)
	c.Assert(builder1.getNumBuilds(), Equals, 1)

	// enqueue builder1
	buildStatus = bq.Enqueue(builder1)

	// Let the build succeed
	builder1.makeBuildReturn(nil)

	buildSuccessful = <-buildStatus
	c.Assert(builder1.getNumBuilds(), Equals, 2)
	c.Assert(buildSuccessful, Equals, true)
}

func (s *BuildQueueTestSuite) TestDrain(c *C) {
	bq := NewBuildQueue("test")
	c.Assert(bq, Not(IsNil))
	defer bq.Stop()

	builder1 := newTestBuilder("builder1")
	bq.Enqueue(builder1)

	// Wait for builder1 to start building
	c.Assert(testutils.WaitUntil(func() bool {
		return builder1.isBuilding()
	}, 2*time.Second), IsNil)

	bq.Enqueue(builder1)
	bq.Enqueue(builder1)
	bq.Enqueue(builder1)
	bq.Enqueue(builder1)

	// Drain in the background and wait
	drainDone := make(chan bool, 1)
	go func() {
		drainDone <- bq.Drain(builder1)
		close(drainDone)
	}()

	// Drain in the background and wait
	drainDone2 := make(chan bool, 1)
	go func() {
		drainDone2 <- bq.Drain(builder1)
		close(drainDone2)
	}()

	time.Sleep(50 * time.Millisecond)

	builder1.makeBuildReturn(nil)

	select {
	case hasWaited := <-drainDone:
		c.Assert(hasWaited, Equals, true)
		// 2nd drain must have waited as well
		c.Assert(<-drainDone2, Equals, true)
	case <-time.After(2 * time.Second):
		c.Fatalf("timeout while waiting for build to drain")
	}

	c.Assert(builder1.getNumQueuedBuilds(), Equals, 0)
}

func (s *BuildQueueTestSuite) TestExclusiveBuild(c *C) {
	bq := NewBuildQueue("test")
	c.Assert(bq, Not(IsNil))
	defer bq.Stop()

	// Enqueue builder1
	builder1 := newTestBuilder("builder1")
	bq.Enqueue(builder1)

	// Wait for builder1 to start building
	c.Assert(testutils.WaitUntil(func() bool {
		return builder1.isBuilding()
	}, 2*time.Second), IsNil)

	// Enqueue a follow-up build of builder1. The build will not start yet
	// as the first build of builder1 is still ongoing. It will be queued.
	bq.Enqueue(builder1)
	c.Assert(builder1.getNumQueuedBuilds(), Equals, 1)

	// Enqueue builder2
	builder2 := newTestBuilder("builder2")
	bq.Enqueue(builder2)

	// Wait for builder2 to start building. The build will start
	// immediately as we have at least 2 workers and builder2 is using a
	// different UUID as builder1.
	c.Assert(testutils.WaitUntil(func() bool {
		return builder2.isBuilding()
	}, 2*time.Second), IsNil)

	// Enqueue a follow-up build of builder2. The build will be queued as
	// the builder2 build is still ongoing.
	bq.Enqueue(builder2)
	c.Assert(builder2.getNumQueuedBuilds(), Equals, 1)

	// Create exclusive builder
	exclusive := newTestBuilder("exclusive")

	// Enqueue a preempt build. The build will be queued as regular builds
	// are still ongoing and exclusive builds require exclusive access to
	// the buildqueue.
	bq.PreemptExclusive(exclusive)
	c.Assert(exclusive.getNumQueuedBuilds(), Equals, 1)

	// Make sure exclusive build does not start. We assume that the build
	// would start within 100 milliseconds.
	c.Assert(testutils.WaitUntil(func() bool {
		return exclusive.isBuilding()
	}, 100*time.Millisecond), Not(IsNil))

	// Let the initial builds of builder1 and builder2 succeed.
	builder1.makeBuildReturn(nil)
	builder2.makeBuildReturn(nil)

	// The exclusive build will have preempted the build queue and will be
	// built next.
	c.Assert(testutils.WaitUntil(func() bool {
		return exclusive.isBuilding()
	}, 2*time.Second), IsNil)
	c.Assert(exclusive.getNumQueuedBuilds(), Equals, 0)

	// Make sure builder1 and builder2 did not start in parallel to the
	// exclusive build.
	c.Assert(testutils.WaitUntil(func() bool {
		return builder1.isBuilding() || builder2.isBuilding()
	}, 100*time.Millisecond), Not(IsNil))

	// Let the first exclusive build finish.
	exclusive.makeBuildReturn(nil)

	// Wait for builder1 and builder2 to start
	c.Assert(testutils.WaitUntil(func() bool {
		return builder1.isBuilding() && builder2.isBuilding()
	}, 2*time.Second), IsNil)

	builder1.makeBuildReturn(nil)
	builder2.makeBuildReturn(nil)

	// exclusive build must have completed and no builds must be scheduled
	c.Assert(exclusive.getNumQueuedBuilds(), Equals, 0)
}

func (s *BuildQueueTestSuite) TestBuildGuarantees(c *C) {
	bq := NewBuildQueue("test")
	c.Assert(bq, Not(IsNil))
	defer bq.Stop()

	allBuilds := sync.WaitGroup{}

	builders := map[int]*testBuilder{}

	for i := 0; i < 256; i++ {
		builder := newTestBuilder(fmt.Sprintf("builder%d", i))
		builder.checkParallel = bq
		builder.completeAfter = time.Millisecond * time.Duration(10+i%32)
		builders[i] = builder

		if i%4 == 0 {
			go func(builder *testBuilder) {
				allBuilds.Add(1)
				c := bq.PreemptExclusive(builder)
				go func() {
					<-c
					allBuilds.Done()
				}()
			}(builder)
		} else {
			go func(builder *testBuilder) {
				for n := 0; n < 8; n++ {
					allBuilds.Add(1)
					c := bq.Enqueue(builder)
					time.Sleep(5 * time.Millisecond)
					go func() {
						<-c
						allBuilds.Done()
					}()
				}
			}(builder)
		}
	}

	allBuilds.Wait()

	for _, builder := range builders {
		c.Assert(builder.queued, Equals, 0)
	}
}
