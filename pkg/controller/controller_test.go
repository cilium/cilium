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

package controller

import (
	"errors"
	"fmt"
	"testing"
	"time"

	. "gopkg.in/check.v1"
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
	waitChan := make(chan bool)

	mngr := Manager{}
	mngr.UpdateController("test", ControllerParams{
		RunInterval: time.Second,
		DoFunc:      NoopFunc,
		StopFunc: func() error {
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
	stopFuncRan := false
	iterations := 0
	waitChan := make(chan bool)

	mngr := Manager{}
	mngr.UpdateController("test", ControllerParams{
		RunInterval: 100 * time.Millisecond,
		DoFunc: func() error {
			iterations++
			return ExitReason{errors.New("test exit")}
		},
		StopFunc: func() error {
			stopFuncRan = true
			close(waitChan)
			return nil
		},
	})
	select {
	case <-waitChan:
	case <-time.After(time.Second):
		c.Error("Controller did not exit")
	}
	c.Assert(iterations, Equals, 1)
	c.Assert(stopFuncRan, Equals, true)
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

	ctrl := mngr.UpdateController("test", ControllerParams{
		DoFunc: func() error {
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
