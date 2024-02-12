// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package job

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/internal"
)

// Timer creates a timer job which can be added to a Group. Timer jobs invoke the given function at the specified
// interval. Timer jobs are particularly useful to implement periodic syncs and cleanup actions.
// Timer jobs can optionally be triggered by an external Trigger with the WithTrigger option.
// This trigger can for example be passed between cells or between jobs in the same cell to allow for an additional
// invocation of the function.
//
// The interval between invocations is counted from the start of the last invocation. If the `fn` takes longer than the
// interval, its next invocation is not delayed. The `fn` is expected to stop as soon as the context passed to it
// expires. This is especially important for long running functions. The signal created by a Trigger is coalesced so
// multiple calls to trigger before the invocation takes place can result in just a single invocation.
func Timer(name string, fn TimerFunc, interval time.Duration, opts ...timerOpt) Job {
	if fn == nil {
		panic("`fn` must not be nil")
	}

	job := &jobTimer{
		name:     name,
		fn:       fn,
		interval: interval,
		opts:     opts,
	}

	return job
}

// TimerFunc is the func type invoked by a timer job. A TimerFunc is expected to return as soon as the ctx expires.
type TimerFunc func(ctx context.Context) error

type timerOpt func(*jobTimer)

// Trigger which can be used to trigger a timer job, trigger events are coalesced.
type Trigger interface {
	_trigger()
	Trigger()
}

// NewTrigger creates a new trigger, which can be used to trigger a timer job.
func NewTrigger() *trigger {
	return &trigger{
		c: make(chan struct{}, 1),
	}
}

type trigger struct {
	c chan struct{}
}

func (t *trigger) _trigger() {}

func (t *trigger) Trigger() {
	select {
	case t.c <- struct{}{}:
	default:
	}
}

// WithTrigger option allows a user to specify a trigger, which if triggered will invoke the function of a timer
// before the configured interval has expired.
func WithTrigger(trig Trigger) timerOpt {
	return func(jt *jobTimer) {
		jt.trigger = trig.(*trigger)
	}
}

type jobTimer struct {
	name string
	fn   TimerFunc
	opts []timerOpt

	health cell.Health

	interval time.Duration
	trigger  *trigger

	// If not nil, call the shutdowner on error
	shutdown hive.Shutdowner
}

func (jt *jobTimer) start(ctx context.Context, wg *sync.WaitGroup, health cell.Health, options options) {
	defer wg.Done()

	for _, opt := range jt.opts {
		opt(jt)
	}

	jt.health = health.NewScope("timer-job-" + jt.name)

	l := options.logger.With(
		"name", jt.name,
		"func", internal.FuncNameAndLocation(jt.fn))

	timer := time.NewTicker(jt.interval)
	defer timer.Stop()

	var triggerChan chan struct{}
	if jt.trigger != nil {
		triggerChan = jt.trigger.c
	}

	l.Debug("Starting timer job")
	jt.health.OK("Primed")

	for {
		select {
		case <-ctx.Done():
			jt.health.Stopped("timer job context done")
			return
		case <-timer.C:
		case <-triggerChan:
		}

		l.Debug("Timer job triggered")

		start := time.Now()
		err := jt.fn(ctx)
		duration := time.Since(start)

		if options.metrics != nil {
			options.metrics.TimerRunDuration(jt.name, duration)
		}

		if err == nil {
			jt.health.OK("OK (" + duration.String() + ")")
			l.Debug("Timer job finished")
		} else if !errors.Is(err, context.Canceled) {
			jt.health.Degraded("timer job errored", err)
			l.Error("Timer job errored", "error", err)

			if options.metrics != nil {
				options.metrics.JobError(jt.name, err)
			}
			if jt.shutdown != nil {
				jt.shutdown.Shutdown(hive.ShutdownWithError(err))
			}
		}

		// If we exited due to the ctx closing we do not guaranteed return.
		// The select can pick the timer or trigger signals over ctx.Done due to fair scheduling, so this guarantees it.
		if ctx.Err() != nil {
			return
		}
	}
}
