// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controller

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/testutils"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ControllerSuite struct{}

var _ = Suite(&ControllerSuite{})

func (b *ControllerSuite) TestUpdateRemoveController(c *C) {
	mngr := NewManager()
	mngr.UpdateController("test", ControllerParams{})
	c.Assert(mngr.RemoveController("test"), IsNil)
	c.Assert(mngr.RemoveController("not-exist"), Not(IsNil))
}

func (b *ControllerSuite) TestStopFunc(c *C) {
	stopFuncRan := false
	waitChan := make(chan struct{})

	mngr := Manager{}
	mngr.UpdateController("test", ControllerParams{
		RunInterval: time.Second,
		DoFunc:      NoopFunc,
		StopFunc: func(ctx context.Context) error {
			stopFuncRan = true
			close(waitChan)
			return nil
		},
	})
	c.Assert(mngr.RemoveController("test"), IsNil)
	select {
	case <-waitChan:
	case <-time.After(2 * time.Second):
		c.Error("StopFunc did not run")
	}
	c.Assert(stopFuncRan, Equals, true)
}

func (b *ControllerSuite) TestSelfExit(c *C) {
	var iterations uint32
	waitChan := make(chan bool)

	mngr := Manager{}
	mngr.UpdateController("test", ControllerParams{
		RunInterval: 100 * time.Millisecond,
		DoFunc: func(ctx context.Context) error {
			atomic.AddUint32(&iterations, 1)
			return NewExitReason("test exit")
		},
		StopFunc: func(ctx context.Context) error {
			close(waitChan)
			return nil
		},
	})
	select {
	case <-waitChan:
		c.Error("Controller exited")
	case <-time.After(time.Second):
	}
	c.Assert(atomic.LoadUint32(&iterations), Equals, uint32(1))

	// The controller is inactive, and waiting for the next update or stop.
	// A controller will only stop when explicitly removed and stopped.
	mngr.RemoveController("test")
	select {
	case <-waitChan:
	case <-time.After(time.Second):
		c.Error("Controller did not exit")
	}
}

func (b *ControllerSuite) TestRemoveAll(c *C) {
	mngr := NewManager()
	// create
	mngr.UpdateController("test1", ControllerParams{})
	mngr.UpdateController("test2", ControllerParams{})
	mngr.UpdateController("test3", ControllerParams{})
	// update
	mngr.UpdateController("test1", ControllerParams{})
	mngr.UpdateController("test2", ControllerParams{})
	mngr.UpdateController("test3", ControllerParams{})
	mngr.RemoveAll()
}

type testObj struct {
	cnt int
}

func (b *ControllerSuite) TestRunController(c *C) {
	mngr := NewManager()
	o := &testObj{}

	ctrl := mngr.updateController("test", ControllerParams{
		DoFunc: func(ctx context.Context) error {
			// after two failed attempts, start succeeding
			if o.cnt >= 2 {
				return nil
			}

			o.cnt++
			return fmt.Errorf("temporary error")
		},
		RunInterval:            time.Duration(1) * time.Millisecond, // short interval
		ErrorRetryBaseDuration: time.Duration(1) * time.Millisecond, // short error retry
	})

	for n := 0; ctrl.GetSuccessCount() < 2; n++ {
		if n > 100 {
			c.Fatalf("time out while waiting for controller to succeed, last error: %s", ctrl.GetLastError())
		}

		time.Sleep(time.Duration(100) * time.Millisecond)
	}

	c.Assert(GetGlobalStatus(), Not(IsNil))

	c.Assert(ctrl.GetSuccessCount(), Not(Equals), 0)
	c.Assert(ctrl.GetFailureCount(), Equals, 2)
	c.Assert(ctrl.GetLastError(), IsNil)
	c.Assert(mngr.RemoveController("test"), IsNil)
}

func (b *ControllerSuite) TestCancellation(c *C) {
	mngr := NewManager()

	started := make(chan struct{})
	cancelled := make(chan struct{})

	mngr.UpdateController("test", ControllerParams{
		DoFunc: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return nil
		},
	})

	// wait for the controller to be running
	select {
	case <-started:
	case <-time.After(time.Minute):
		c.Fatalf("timeout while waiting for controller to start")
	}

	mngr.RemoveAll()

	// wait for the controller to be cancelled
	select {
	case <-cancelled:
	case <-time.After(time.Minute):
		c.Fatalf("timeout while waiting for controller to be cancelled")
	}
}

func (b *ControllerSuite) TestWaitForTermination(c *C) {
	mngr := NewManager()
	mngr.UpdateController("test1", ControllerParams{})
	mngr.UpdateController("test1", ControllerParams{})

	// Ensure that the channel does not get closed while the controller is
	// still running
	c.Assert(testutils.WaitUntil(func() bool {
		select {
		case <-mngr.TerminationChannel("test1"):
			return false
		default:
			return true
		}
	}, 20*time.Millisecond), IsNil)

	c.Assert(mngr.RemoveControllerAndWait("test1"), IsNil)

	// The controller must have been terminated already due to AndWait above
	select {
	case <-mngr.TerminationChannel("test1"):
	default:
		c.Fail()
	}
}
