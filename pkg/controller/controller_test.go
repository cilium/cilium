// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controller

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestUpdateRemoveController(t *testing.T) {
	mngr := NewManager()
	mngr.UpdateController("test", ControllerParams{})
	require.NoError(t, mngr.RemoveController("test"))
	require.Error(t, mngr.RemoveController("not-exits"))
}

func TestCreateController(t *testing.T) {
	var iterations atomic.Uint32
	mngr := NewManager()
	created := mngr.CreateController("test", ControllerParams{
		DoFunc: func(ctx context.Context) error {
			iterations.Add(1)
			return nil
		},
	})
	require.True(t, created)

	// Second creation is a no-op.
	created = mngr.CreateController("test", ControllerParams{
		DoFunc: func(ctx context.Context) error {
			iterations.Add(1)
			return nil
		},
	})
	require.False(t, created)

	require.NoError(t, mngr.RemoveControllerAndWait("test"))
	require.Equal(t, uint32(1), iterations.Load())
}

func TestStopFunc(t *testing.T) {
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
	require.NoError(t, mngr.RemoveController("test"))
	select {
	case <-waitChan:
	case <-time.After(2 * time.Second):
		t.Error("StopFunc did not run")
	}
	require.True(t, stopFuncRan)
}

func TestSelfExit(t *testing.T) {
	var iterations atomic.Uint32
	waitChan := make(chan bool)

	mngr := Manager{}
	mngr.UpdateController("test", ControllerParams{
		RunInterval: 100 * time.Millisecond,
		DoFunc: func(ctx context.Context) error {
			iterations.Add(1)
			return NewExitReason("test exit")
		},
		StopFunc: func(ctx context.Context) error {
			close(waitChan)
			return nil
		},
	})
	select {
	case <-waitChan:
		t.Error("Controller exited")
	case <-time.After(time.Second):
	}
	require.Equal(t, uint32(1), iterations.Load())

	// The controller is inactive, and waiting for the next update or stop.
	// A controller will only stop when explicitly removed and stopped.
	mngr.RemoveController("test")
	select {
	case <-waitChan:
	case <-time.After(time.Second):
		t.Error("Controller did not exit")
	}
}

func TestRemoveAll(t *testing.T) {
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

func TestRunController(t *testing.T) {
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
			t.Fatalf("time out while waiting for controller to succeed, last error: %s", ctrl.GetLastError())
		}

		time.Sleep(time.Duration(100) * time.Millisecond)
	}

	require.NotNil(t, GetGlobalStatus())
	require.NotEqual(t, 0, ctrl.GetSuccessCount())
	require.Equal(t, 2, ctrl.GetFailureCount())
	require.NoError(t, ctrl.GetLastError())
	require.NoError(t, mngr.RemoveController("test"))
}

func TestCancellation(t *testing.T) {
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
		t.Fatalf("timeout while waiting for controller to start")
	}

	mngr.RemoveAll()

	// wait for the controller to be cancelled
	select {
	case <-cancelled:
	case <-time.After(time.Minute):
		t.Fatalf("timeout while waiting for controller to be cancelled")
	}
}

// terminationChannel returns a channel that is closed after the controller has
// been terminated
func (m *Manager) terminationChannel(name string) chan struct{} {
	if c := m.lookup(name); c != nil {
		return c.terminated
	}

	c := make(chan struct{})
	close(c)
	return c
}

func TestWaitForTermination(t *testing.T) {
	mngr := NewManager()
	mngr.UpdateController("test1", ControllerParams{})
	mngr.UpdateController("test1", ControllerParams{})

	// Ensure that the channel does not get closed while the controller is
	// still running
	require.NoError(t, testutils.WaitUntil(func() bool {
		select {
		case <-mngr.terminationChannel("test1"):
			return false
		default:
			return true
		}
	}, 20*time.Millisecond))

	require.NoError(t, mngr.RemoveControllerAndWait("test1"))

	// The controller must have been terminated already due to AndWait above
	select {
	case <-mngr.terminationChannel("test1"):
	default:
		t.Fail()
	}
}

func TestTriggerController(t *testing.T) {
	mngr := NewManager()

	ctrl := mngr.updateController("test", ControllerParams{
		DoFunc: func(ctx context.Context) error {
			return nil
		},
		RunInterval:        time.Duration(10) * time.Second, // A long interval to avoid interference
		MinTriggerInterval: time.Duration(2) * time.Second,
	})

	var firstTimeStamp time.Time
	var secondTimeStamp time.Time
	for n := 0; ctrl.GetSuccessCount() < 3; n++ {
		if n > 100 {
			t.Fatalf("time out while waiting for controller to succeed, last error: %s", ctrl.GetLastError())
		}
		mngr.TriggerController("test")
		if ctrl.GetSuccessCount() == 1 {
			firstTimeStamp = ctrl.lastSuccessStamp
			mngr.TriggerController("test")
		}

		if ctrl.GetSuccessCount() == 2 {
			secondTimeStamp = ctrl.lastSuccessStamp
			timeDiff := secondTimeStamp.Sub(firstTimeStamp)
			require.Less(t, timeDiff, time.Duration(2100)*time.Millisecond)
			require.Greater(t, timeDiff, time.Duration(1900)*time.Millisecond)
		}

		time.Sleep(time.Duration(100) * time.Millisecond) // To make sure the timestamp is updated before the next check
	}

	require.NoError(t, ctrl.GetLastError())
	require.NoError(t, mngr.RemoveController("test"))
}
