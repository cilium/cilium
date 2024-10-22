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

// Timer creates a timer job which can be added to a Group.
// The Timer job name must match regex "^[a-z][a-z0-9_\\-]{0,100}$". The function passed is invoked at the specified interval.
// Timer jobs are particularly useful to implement periodic syncs and cleanup actions.
// Timer jobs can optionally be triggered by an external Trigger with the WithTrigger option.
// This trigger can for example be passed between cells or between jobs in the same cell to allow for an additional
// invocation of the function.
//
// The interval between invocations is counted from the start of the last invocation. If the `fn` takes longer than the
// interval, its next invocation is not delayed. The `fn` is expected to stop as soon as the context passed to it
// expires. This is especially important for long running functions. The signal created by a Trigger is coalesced so
// multiple calls to trigger before the invocation takes place can result in just a single invocation.
func Timer(name string, fn TimerFunc, interval time.Duration, opts ...timerOpt) Job {
	if err := validateName(name); err != nil {
		panic(err)
	}
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
func NewTrigger(opts ...triggerOpt) *trigger {
	t := &trigger{
		c: make(chan struct{}, 1),
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// WithDebounce allows to specify an interval over with multiple trigger requests will be folded into one.
func WithDebounce(interval time.Duration) triggerOpt {
	return func(t *trigger) {
		t.debounce = interval
	}
}

type trigger struct {
	debounce time.Duration

	mu            sync.Mutex
	c             chan struct{}
	lastTriggered time.Time
	folds         int
	waitStart     time.Time
}

func (t *trigger) _trigger() {}

func (t *trigger) Trigger() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.folds == 0 {
		t.waitStart = time.Now()
	}
	t.folds++

	if t.debounce > 0 && time.Since(t.lastTriggered) < t.debounce {
		return
	}

	select {
	case t.c <- struct{}{}:
	default:
	}
}

func (t *trigger) markTriggered(name string, metrics Metrics) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.lastTriggered = time.Now()
	if metrics != nil {
		metrics.TimerTriggerStats(name, t.lastTriggered.Sub(t.waitStart), t.folds)
	}
	t.folds = 0

	// discard a possibly enqueued trigger notification.
	// This is needed when a notification is already enqueued in the channel (and thus has already passed the debounce check)
	// but the fair scheduling receives from the ticker channel.
	select {
	case <-t.c:
	default:
	}
}

type triggerOpt func(t *trigger)

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

	var tickerChan <-chan time.Time
	if jt.interval > 0 {
		ticker := time.NewTicker(jt.interval)
		defer ticker.Stop()
		tickerChan = ticker.C
	}

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
		case <-tickerChan:
		case <-triggerChan:
		}

		l.Debug("Timer job triggered")

		if jt.trigger != nil {
			jt.trigger.markTriggered(jt.name, options.metrics)
		}

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
