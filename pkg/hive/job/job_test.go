// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package job

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/stream"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
	"k8s.io/client-go/util/workqueue"
)

func TestMain(m *testing.M) {
	cleanup := func(exitCode int) {
		// Force garbage-collection to force finalizers to run and catch
		// missing Event.Done() calls.
		runtime.GC()
	}
	goleak.VerifyTestMain(m, goleak.Cleanup(cleanup))
}

func fixture(fn func(Registry, hive.Lifecycle)) *hive.Hive {
	logging.SetLogLevel(logrus.DebugLevel)
	return hive.New(
		Cell,
		cell.Invoke(fn),
	)
}

// This test asserts that a OneShot jobs is started and completes. This test will timeout on failure
func TestOneShot_ShortRun(t *testing.T) {
	stop := make(chan struct{})

	h := fixture(func(r Registry, l hive.Lifecycle) {
		g := r.NewGroup()

		g.Add(
			OneShot("short", func(ctx context.Context) error {
				defer close(stop)
				return nil
			}),
		)

		l.Append(g)
	})

	if assert.NoError(t, h.Start(context.Background())) {
		<-stop
		assert.NoError(t, h.Stop(context.Background()))
	}
}

// This test asserts that the context given to a one shot job cancels when the lifecycle of the group ends.
func TestOneShot_LongRun(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})

	h := fixture(func(r Registry, l hive.Lifecycle) {
		g := r.NewGroup()

		g.Add(
			OneShot("long", func(ctx context.Context) error {
				close(started)
				<-ctx.Done()
				defer close(stopped)
				return nil
			}),
		)

		l.Append(g)
	})

	if assert.NoError(t, h.Start(context.Background())) {
		<-started
		assert.NoError(t, h.Stop(context.Background()))
		<-stopped
	}
}

// This test asserts that we will stop retrying after the retry limit
func TestOneShot_RetryFail(t *testing.T) {
	var (
		g Group
		i int
	)

	const retries = 3

	h := fixture(func(r Registry, l hive.Lifecycle) {
		g = r.NewGroup()

		g.Add(
			OneShot("retry-fail", func(ctx context.Context) error {
				defer func() { i++ }()
				return errors.New("Always error")
			}, WithRetry(retries, workqueue.DefaultControllerRateLimiter())),
		)

		l.Append(g)
	})

	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Continue as soon as all jobs stopped
	g.(*group).wg.Wait()

	if err := h.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	// 1 for the initial run, and 3 retries
	if i != retries+1 {
		t.Fatalf("Retries = %d, Ran = %d", retries, i)
	}
}

// Run the actual test multiple times, as long as 1 out of 5 is good, we accept it, only fail if we are consistently
// broken. This is due to the time based nature of the test which is unreliable in certain CI environments.
func TestOneShot_RetryBackoff(t *testing.T) {
	ok := 0
	for i := 0; i < 5; i++ {
		failed, err := testOneShot_RetryBackoff()
		if err != nil {
			t.Fatal(err)
		}
		if !failed {
			ok++
		}
	}

	if ok == 0 {
		t.Fatal("0/5 retry backoff tests succeeded")
	}
}

// This test asserts that the one shot jobs have a delay equal to the expected behavior of the passed in ratelimiter.
func testOneShot_RetryBackoff() (bool, error) {
	var (
		g     Group
		i     int
		times []time.Time
	)

	failed := false

	const retries = 6

	h := fixture(func(r Registry, l hive.Lifecycle) {
		g = r.NewGroup()

		g.Add(
			OneShot("retry-backoff", func(ctx context.Context) error {
				defer func() { i++ }()
				times = append(times, time.Now())
				return errors.New("Always error")
			}, WithRetry(retries, workqueue.NewItemExponentialFailureRateLimiter(50*time.Millisecond, 10*time.Second))),
		)

		l.Append(g)
	})

	if err := h.Start(context.Background()); err != nil {
		return true, err
	}

	// Continue as soon as all jobs stopped
	g.(*group).wg.Wait()

	if err := h.Stop(context.Background()); err != nil {
		return true, err
	}

	var last time.Duration
	for i := 1; i < len(times); i++ {
		diff := times[i].Sub(times[i-1])
		if i > 2 {
			// Test that the rate of change is 2 +- 50%, the 50% to account for CI time dilation.
			// The 10 factor is to add avoid integer rounding.
			fract := uint64(diff * 10 / last * 10)
			if fract < 150 || fract > 250 {
				failed = true
			}
		}
		last = diff
	}

	return failed, nil
}

// This test asserts that we do not keep retrying after the job function has recovered
func TestOneShot_RetryRecover(t *testing.T) {
	var (
		g Group
		i int
	)

	const retries = 3

	h := fixture(func(r Registry, l hive.Lifecycle) {
		g = r.NewGroup()

		g.Add(
			OneShot("retry-recover", func(ctx context.Context) error {
				defer func() { i++ }()
				if i == 0 {
					return errors.New("Sometimes error")
				}

				return nil
			}, WithRetry(retries, workqueue.DefaultControllerRateLimiter())),
		)

		l.Append(g)
	})

	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Continue as soon as all jobs stopped
	g.(*group).wg.Wait()

	if err := h.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	if i != 2 {
		t.Fatal("One shot was invoked after the recovery")
	}
}

// This tests asserts that returning an error on a one shot job with the WithShutdown option will shutdown the hive.
func TestOneShot_Shutdown(t *testing.T) {
	targetErr := errors.New("Always error")
	h := fixture(func(r Registry, l hive.Lifecycle) {
		g := r.NewGroup()

		g.Add(
			OneShot("shutdown", func(ctx context.Context) error {
				return targetErr
			}, WithShutdown()),
		)

		l.Append(g)
	})

	err := h.Run()
	if !errors.Is(err, targetErr) {
		t.Fail()
	}
}

// This test asserts that when the retry and shutdown options are used, the hive is only shutdown after all retries
// failed
func TestOneShot_RetryFailShutdown(t *testing.T) {
	var i int

	const retries = 3

	targetErr := errors.New("Always error")
	h := fixture(func(r Registry, l hive.Lifecycle) {
		g := r.NewGroup()

		g.Add(
			OneShot("retry-fail-shutdown", func(ctx context.Context) error {
				defer func() { i++ }()
				return targetErr
			}, WithRetry(retries, workqueue.DefaultControllerRateLimiter()), WithShutdown()),
		)

		l.Append(g)
	})

	err := h.Run()
	if !errors.Is(err, targetErr) {
		t.Fail()
	}

	if i != retries+1 {
		t.Fail()
	}
}

// This test asserts that when both the WithRetry and WithShutdown options are used, and the one shot function recovers
// that the hive does not shutdown.
func TestOneShot_RetryRecoverNoShutdown(t *testing.T) {
	var (
		g Group
		i int
	)

	started := make(chan struct{})

	const retries = 5

	h := fixture(func(r Registry, l hive.Lifecycle) {
		g = r.NewGroup()

		g.Add(
			OneShot("retry-recover-no-shutdown", func(ctx context.Context) error {
				defer func() { i++ }()

				if i == 0 {
					close(started)
					return errors.New("First try error")
				}

				return nil
			}, WithRetry(retries, workqueue.DefaultControllerRateLimiter()), WithShutdown()),
		)

		l.Append(g)
	})

	shutdown := make(chan struct{})

	// Manually trigger a shutdown after the group has no more running jobs, will exit the hive with a nil
	go func() {
		<-started
		g.(*group).wg.Wait()
		h.Shutdown()
		close(shutdown)
	}()

	err := h.Run()
	if err != nil {
		t.Fatal(err)
	}

	if i != 2 {
		t.Fail()
	}

	<-shutdown
}

// This test ensures that the timer function is called repeatedly.
// Not testing the timer interval is intentional, as there are no guarantees for test execution
// timeliness in the CI or even locally. This makes assertions of test timing inherently flaky,
// leading to a need of large tolerances that diminish value of such assertions.
func TestTimer_OnInterval(t *testing.T) {
	stop := make(chan struct{})
	i := 0

	h := fixture(func(r Registry, l hive.Lifecycle) {
		g := r.NewGroup()

		g.Add(
			Timer("on-interval", func(ctx context.Context) error {
				// Close the stop channel after 5 invocations.
				i++
				if i == 5 {
					close(stop)
				}
				return nil
			}, 100*time.Millisecond),
		)

		l.Append(g)
	})

	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-stop

	if err := h.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// This test asserts that a timer will run when triggered, even when its interval has not yet expired
func TestTimer_Trigger(t *testing.T) {
	ran := make(chan struct{})

	var i int

	trigger := NewTrigger()

	h := fixture(func(r Registry, l hive.Lifecycle) {
		g := r.NewGroup()

		g.Add(
			Timer("on-interval", func(ctx context.Context) error {
				defer func() { ran <- struct{}{} }()

				i++

				return nil
			}, 1*time.Hour, WithTrigger(trigger)),
		)

		l.Append(g)
	})

	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	trigger.Trigger()
	<-ran

	trigger.Trigger()
	<-ran

	trigger.Trigger()
	<-ran

	if err := h.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	if i != 3 {
		t.Fail()
	}
}

// This test asserts that, if a trigger is called multiple times before a job is finished, that the events will coalesce
func TestTimer_DoubleTrigger(t *testing.T) {
	ran := make(chan struct{})

	var i int

	trigger := NewTrigger()

	h := fixture(func(r Registry, l hive.Lifecycle) {
		g := r.NewGroup()

		g.Add(
			Timer("on-interval", func(ctx context.Context) error {
				defer func() { close(ran) }()

				i++

				time.Sleep(100 * time.Millisecond)

				return nil
			}, 1*time.Hour, WithTrigger(trigger)),
		)

		l.Append(g)
	})

	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	trigger.Trigger()
	trigger.Trigger()
	trigger.Trigger()
	<-ran

	if err := h.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	if i != 1 {
		t.Fail()
	}
}

// This test asserts that the timer will stop as soon as the lifecycle has stopped, when waiting for an interval pulse
func TestTimer_ExitOnClose(t *testing.T) {
	var i int
	h := fixture(func(r Registry, l hive.Lifecycle) {
		g := r.NewGroup()

		g.Add(
			Timer("on-interval", func(ctx context.Context) error {
				i++
				return nil
			}, 1*time.Hour),
		)

		l.Append(g)
	})

	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := h.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	if i != 0 {
		t.Fail()
	}
}

// This test asserts that the context given to the timer closes when the lifecycle ends, and that the timer stops
// after the fn return.
func TestTimer_ExitOnCloseFnCtx(t *testing.T) {
	var i int
	started := make(chan struct{})
	h := fixture(func(r Registry, l hive.Lifecycle) {
		g := r.NewGroup()

		g.Add(
			Timer("on-interval", func(ctx context.Context) error {
				i++
				if started != nil {
					close(started)
					started = nil
				}
				<-ctx.Done()
				return nil
			}, 1*time.Millisecond),
		)

		l.Append(g)
	})

	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-started

	if err := h.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	if i != 1 {
		t.Fail()
	}
}

// This test asserts that an observer job will stop after a stream has been completed.
func TestObserver_ShortStream(t *testing.T) {
	var (
		g Group
		i int
	)

	streamSlice := []string{"a", "b", "c"}

	h := fixture(func(r Registry, l hive.Lifecycle) {
		g = r.NewGroup()

		g.Add(
			Observer("retry-fail", func(ctx context.Context, event string) error {
				i++
				return nil
			}, stream.FromSlice(streamSlice)),
		)

		l.Append(g)
	})

	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Continue as soon as all jobs stopped
	g.(*group).wg.Wait()

	if err := h.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	if i != len(streamSlice) {
		t.Fatal()
	}
}

// This test asserts that the observer will stop without errors when the lifecycle ends, even if the stream has not
// gone away.
func TestObserver_LongStream(t *testing.T) {
	var (
		g Group
		i int
	)

	inChan := make(chan struct{})

	h := fixture(func(r Registry, l hive.Lifecycle) {
		g = r.NewGroup()

		g.Add(
			Observer("retry-fail", func(ctx context.Context, _ struct{}) error {
				i++
				return nil
			}, stream.FromChannel(inChan)),
		)

		l.Append(g)
	})

	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := h.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	if i != 0 {
		t.Fatal()
	}
}

// This test asserts that the context given to the observer fn is closed when the lifecycle ends and the observer
// stops even if there are still pending items in the stream.
func TestObserver_CtxClose(t *testing.T) {
	started := make(chan struct{})
	i := 0
	streamSlice := []string{"a", "b", "c"}

	h := fixture(func(r Registry, l hive.Lifecycle) {
		g := r.NewGroup()

		g.Add(
			Observer("retry-fail", func(ctx context.Context, event string) error {
				if i == 0 {
					close(started)
					i++
				}
				<-ctx.Done()
				return nil
			}, stream.FromSlice(streamSlice)),
		)

		l.Append(g)
	})

	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-started

	if err := h.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// This test asserts that the test registry hold on to references to its groups
func TestRegistry(t *testing.T) {
	var (
		r1 Registry
		g1 Group
		g2 Group
	)

	h := fixture(func(r Registry, l hive.Lifecycle) {
		r1 = r
		g1 = r.NewGroup()
		g2 = r.NewGroup()
	})
	h.Populate()

	if r1.(*registry).groups[0] != g1 {
		t.Fail()
	}
	if r1.(*registry).groups[1] != g2 {
		t.Fail()
	}
}

// This test asserts that jobs are queued, until the hive has been started
func TestGroup_JobQueue(t *testing.T) {
	h := fixture(func(r Registry, l hive.Lifecycle) {
		g := r.NewGroup()
		g.Add(
			OneShot("queued1", func(ctx context.Context) error { return nil }),
			OneShot("queued2", func(ctx context.Context) error { return nil }),
		)
		g.Add(
			OneShot("queued3", func(ctx context.Context) error { return nil }),
			OneShot("queued4", func(ctx context.Context) error { return nil }),
		)
		if len(g.(*group).queuedJobs) != 4 {
			t.Fatal()
		}
		l.Append(g)
	})

	h.Populate()
}

// This test asserts that jobs can be added at runtime.
func TestGroup_JobRuntime(t *testing.T) {
	var (
		g Group
		i int
	)

	h := fixture(func(r Registry, l hive.Lifecycle) {
		g = r.NewGroup()
		l.Append(g)
	})

	h.Start(context.Background())

	done := make(chan struct{})
	g.Add(OneShot("runtime", func(ctx context.Context) error {
		i++
		close(done)
		return nil
	}))

	h.Stop(context.Background())

	if i != 1 {
		t.Fatal()
	}
}
