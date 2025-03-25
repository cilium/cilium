// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package trigger

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/lock"
)

func TestNeedsDelay(t *testing.T) {
	tr := &Trigger{params: Parameters{}}

	needsDelay, _ := tr.needsDelay()
	require.False(t, needsDelay)

	tr.params.MinInterval = time.Second

	tr.lastTrigger = time.Now().Add(time.Second * -2)
	needsDelay, _ = tr.needsDelay()
	require.False(t, needsDelay)

	tr.lastTrigger = time.Now().Add(time.Millisecond * -900)
	needsDelay, _ = tr.needsDelay()
	require.True(t, needsDelay)
	time.Sleep(time.Millisecond * 200)
	needsDelay, _ = tr.needsDelay()
	require.False(t, needsDelay)
}

func TestMinInterval(t *testing.T) {
	var (
		mutex     lock.Mutex
		triggered int
	)

	tr, err := NewTrigger(Parameters{
		TriggerFunc: func(reasons []string) {
			mutex.Lock()
			triggered++
			mutex.Unlock()
		},
		MinInterval:   time.Millisecond * 500,
		sleepInterval: time.Millisecond,
	})
	require.NoError(t, err)
	require.NotNil(t, tr)

	for range 5 {
		tr.Trigger()
		time.Sleep(time.Millisecond * 20)
	}

	mutex.Lock()
	triggeredCopy := triggered
	mutex.Unlock()
	require.Equal(t, 1, triggeredCopy)

	tr.Shutdown()
}

func TestLongTrigger(t *testing.T) {
	var (
		mutex     lock.Mutex
		triggered int
	)

	tr, err := NewTrigger(Parameters{
		TriggerFunc: func(reasons []string) {
			mutex.Lock()
			triggered++
			mutex.Unlock()
			time.Sleep(time.Second)
		},
		sleepInterval: time.Millisecond,
	})
	require.NoError(t, err)
	require.NotNil(t, tr)

	for range 5 {
		tr.Trigger()
		time.Sleep(time.Millisecond * 20)
	}

	mutex.Lock()
	triggeredCopy := triggered
	mutex.Unlock()
	require.Equal(t, 1, triggeredCopy)

	tr.Shutdown()
}

func TestShutdownFunc(t *testing.T) {
	done := make(chan struct{})
	tr, err := NewTrigger(Parameters{
		TriggerFunc: func(reasons []string) {},
		ShutdownFunc: func() {
			close(done)
		},
	})
	require.NoError(t, err)

	tr.Trigger()
	select {
	case <-done:
		t.Errorf("shutdown func called unexpectedly")
	default:
	}

	tr.Shutdown()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Errorf("timed out while waiting for shutdown func")
	}
}

func BenchmarkUntriggeredTrigger(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		tr, err := NewTrigger(Parameters{
			TriggerFunc:   func(reasons []string) {},
			ShutdownFunc:  func() {},
			sleepInterval: time.Millisecond,
		})
		require.NoError(b, err)

		time.Sleep(time.Millisecond * 50)
		tr.Shutdown()
	}
}
