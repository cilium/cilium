// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package job

import (
	"context"
	"errors"
	"runtime/pprof"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/internal"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/stream"
)

// Cell provides job.Registry which constructs job.Group-s. Job groups automate a lot of the logic involved with
// lifecycle management of goroutines within a Hive Cell. Providing a context that is canceled on shutdown and making
// sure multiple goroutines properly shutdown takes a lot of boilerplate. Job groups make it easy to queue, spawn, and
// collect jobs with minimal boilerplate. The registry maintains references to all groups which will allow us to add
// automatic metrics collection and/or status reporting in the future.
var Cell = cell.Module(
	"jobs",
	"Jobs",
	cell.Provide(newRegistry),
	cell.Metric(newJobMetrics),
)

// A Registry creates Groups, it maintains references to these groups for the purposes of collecting information
// centralized like metrics.
type Registry interface {
	// NewGroup creates a new group of jobs which can be started and stopped together as part of the cells lifecycle.
	// The provided scope is used to report health status of the jobs. A `cell.Scope` can be obtained via injection
	// an object with the correct scope is provided by the closest `cell.Module`.
	NewGroup(scope cell.Scope, opts ...groupOpt) Group
}

type registry struct {
	logger     logrus.FieldLogger
	shutdowner hive.Shutdowner

	metrics *jobMetrics

	mu     lock.Mutex
	groups []Group
}

func newRegistry(
	logger logrus.FieldLogger,
	shutdowner hive.Shutdowner,
	metrics *jobMetrics,
) Registry {
	return &registry{
		logger:     logger,
		shutdowner: shutdowner,
		metrics:    metrics,
	}
}

// NewGroup creates a new Group with the given `opts` options, which allows you to customize the behavior for the
// group as a whole. For example by allowing you to add pprof labels to the group or by customizing the logger.
func (c *registry) NewGroup(scope cell.Scope, opts ...groupOpt) Group {
	c.mu.Lock()
	defer c.mu.Unlock()

	var options options
	options.logger = c.logger
	options.shutdowner = c.shutdowner
	options.metrics = c.metrics

	for _, opt := range opts {
		opt(&options)
	}

	g := &group{
		options: options,
		wg:      &sync.WaitGroup{},
		scope:   scope,
	}

	c.groups = append(c.groups, g)

	return g
}

// Group aims to streamline the management of work within a cell. Group implements cell.HookInterface and takes care
// of proper start and stop behavior as expected by hive. A group allows you to add multiple types of jobs which
// different kinds of logic. No matter the job type, the function provided to is always called with a context which
// is bound to the lifecycle of the cell.
type Group interface {
	Add(...Job)
	// Scoped creates a scroped group, jobs added to this scoped group will appear as a sub scope in the health reporter
	Scoped(name string) ScopedGroup
	cell.HookInterface
}

// Job in an interface that describes a unit of work which can be added to a Group. This interface contains unexported
// methods and thus can only be implemented by functions in this package such as OneShot, Timer, or Observer.
type Job interface {
	start(ctx context.Context, wg *sync.WaitGroup, scope cell.Scope, options options)
}

type group struct {
	options options

	wg *sync.WaitGroup

	mu         lock.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	queuedJobs []Job

	scope cell.Scope
}

type options struct {
	pprofLabels pprof.LabelSet
	logger      logrus.FieldLogger
	shutdowner  hive.Shutdowner
	metrics     *jobMetrics
}

type groupOpt func(o *options)

// WithLogger replaces the default logger with the given logger, useful if you want to add certain fields to the logs
// created by the group/jobs.
func WithLogger(logger logrus.FieldLogger) groupOpt {
	return func(o *options) {
		o.logger = logger
	}
}

// WithPprofLabels adds pprof labels which will be added to the goroutines spawned for the jobs and thus included in
// the pprof profiles.
func WithPprofLabels(pprofLabels pprof.LabelSet) groupOpt {
	return func(o *options) {
		o.pprofLabels = pprofLabels
	}
}

var _ cell.HookInterface = (*group)(nil)

// Start implements the cell.HookInterface interface
func (jg *group) Start(_ cell.HookContext) error {
	jg.mu.Lock()
	defer jg.mu.Unlock()

	jg.ctx, jg.cancel = context.WithCancel(context.Background())

	jg.wg.Add(len(jg.queuedJobs))
	for _, job := range jg.queuedJobs {
		pprof.Do(jg.ctx, jg.options.pprofLabels, func(ctx context.Context) {
			go job.start(ctx, jg.wg, jg.scope, jg.options)
		})
	}
	// Nil the queue once we start so it can be GC'ed
	jg.queuedJobs = nil

	return nil
}

// Stop implements the cell.HookInterface interface
func (jg *group) Stop(stopCtx cell.HookContext) error {
	jg.mu.Lock()
	defer jg.mu.Unlock()

	done := make(chan struct{})
	go func() {
		jg.wg.Wait()
		close(done)
	}()

	jg.cancel()

	select {
	case <-stopCtx.Done():
		jg.options.logger.Error("Stop hook context expired before job group was done")
	case <-done:
	}

	return nil
}

func (jg *group) Add(jobs ...Job) {
	jg.add(jg.scope, jobs...)
}

func (jg *group) add(scope cell.Scope, jobs ...Job) {
	jg.mu.Lock()
	defer jg.mu.Unlock()

	// The context is only set once the group has been started. If we have not yet started, queue the jobs.
	if jg.ctx == nil {
		jg.queuedJobs = append(jg.queuedJobs, jobs...)
		return
	}

	for _, j := range jobs {
		jg.wg.Add(1)
		pprof.Do(jg.ctx, jg.options.pprofLabels, func(ctx context.Context) {
			go j.start(ctx, jg.wg, scope, jg.options)
		})
	}
}

// Scoped creates a scroped group, jobs added to this scoped group will appear as a sub scope in the health reporter
func (jg *group) Scoped(name string) ScopedGroup {
	return &scopedGroup{
		group: jg,
		scope: cell.GetSubScope(jg.scope, name),
	}
}

type ScopedGroup interface {
	Add(jobs ...Job)
}

type scopedGroup struct {
	group *group
	scope cell.Scope
}

func (sg *scopedGroup) Add(jobs ...Job) {
	sg.group.add(sg.scope, jobs...)
}

// OneShot creates a "One shot" job which can be added to a Group. The function passed to a one shot job is invoked
// once at startup. It can live for the entire lifetime of the group or exit early depending on its task.
// If it returns an error, it can optionally be retried if the WithRetry option. If retries are not configured or
// all retries failed as well, a shutdown of the hive can be triggered by specifying the WithShutdown option.
//
// The given function is expected to exit as soon as the context given to it expires, this is especially important for
// blocking or long running jobs.
func OneShot(name string, fn OneShotFunc, opts ...jobOneShotOpt) Job {
	if fn == nil {
		panic("`fn` must not be nil")
	}

	job := &jobOneShot{
		name: name,
		fn:   fn,
		opts: opts,
	}

	return job
}

type jobOneShotOpt func(*jobOneShot)

// WithRetry option configures a one shot job to retry `times` amount of times. Each retry attempt the `backoff`
// ratelimiter is consulted to check how long the job should wait before making another attempt.
func WithRetry(times int, backoff workqueue.RateLimiter) jobOneShotOpt {
	return func(jos *jobOneShot) {
		jos.retry = times
		jos.backoff = backoff
	}
}

// WithShutdown option configures a one shot job to shutdown the whole hive if the job returns an error. If the
// WithRetry option is also configured, all retries must be exhausted before we trigger the shutdown.
func WithShutdown() jobOneShotOpt {
	return func(jos *jobOneShot) {
		jos.shutdownOnError = true
	}
}

// WithMetrics option enabled metrics collection for this one shot job. This option should only be used
// for short running jobs. Metrics use the jobs name as label, so if jobs are spawned dynamically
// make sure to use the same job name to keep metric cardinality low.
func WithMetrics() jobOneShotOpt {
	return func(jos *jobOneShot) {
		jos.metrics = true
	}
}

// OneShotFunc is the function type which is invoked by a one shot job. The given function is expected to exit as soon
// as the context given to it expires, this is especially important for blocking or long running jobs.
type OneShotFunc func(ctx context.Context, health cell.HealthReporter) error

type jobOneShot struct {
	name string
	fn   OneShotFunc
	opts []jobOneShotOpt

	health cell.HealthReporter

	// If retry > 0, retry on error x times.
	retry           int
	backoff         workqueue.RateLimiter
	shutdownOnError bool
	metrics         bool
}

func (jos *jobOneShot) start(ctx context.Context, wg *sync.WaitGroup, scope cell.Scope, options options) {
	defer wg.Done()

	for _, opt := range jos.opts {
		opt(jos)
	}

	jos.health = cell.GetHealthReporter(scope, "job-"+jos.name)
	defer jos.health.Stopped("one-shot job done")

	l := options.logger.WithFields(logrus.Fields{
		"name": jos.name,
		"func": internal.FuncNameAndLocation(jos.fn),
	})

	stat := &spanstat.SpanStat{}

	timer, cancel := inctimer.New()
	defer cancel()

	var err error
	for i := 0; i <= jos.retry; i++ {
		var timeout time.Duration
		if i != 0 {
			timeout = jos.backoff.When(jos)
			l.WithFields(logrus.Fields{
				"backoff":     timeout,
				"retry-count": i,
			}).Debug("Delaying retry attempt")
		}

		select {
		case <-ctx.Done():
			return
		case <-timer.After(timeout):
		}

		l.Debug("Starting one-shot job")

		if jos.metrics {
			stat.Start()
		}

		jos.health.OK("Running")
		err = jos.fn(ctx, jos.health)

		if jos.metrics {
			sec := stat.End(true).Seconds()
			options.metrics.OneShotRunDuration.WithLabelValues(jos.name).Observe(sec)
			stat.Reset()
		}

		if err == nil {
			return
		} else if !errors.Is(err, context.Canceled) {
			jos.health.Degraded("one-shot job errored", err)
			l.WithError(err).Error("one-shot job errored")
			options.metrics.JobErrorsTotal.WithLabelValues(jos.name).Inc()
		}
	}

	if options.shutdowner != nil && jos.shutdownOnError {
		options.shutdowner.Shutdown(hive.ShutdownWithError(err))
	}
}

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

	health cell.HealthReporter

	interval time.Duration
	trigger  *trigger

	// If not nil, call the shutdowner on error
	shutdown hive.Shutdowner
}

func (jt *jobTimer) start(ctx context.Context, wg *sync.WaitGroup, scope cell.Scope, options options) {
	defer wg.Done()

	for _, opt := range jt.opts {
		opt(jt)
	}

	jt.health = cell.GetHealthReporter(scope, "timer-job-"+jt.name)

	l := options.logger.WithFields(logrus.Fields{
		"name": jt.name,
		"func": internal.FuncNameAndLocation(jt.fn),
	})

	timer := time.NewTicker(jt.interval)
	defer timer.Stop()

	var triggerChan chan struct{}
	if jt.trigger != nil {
		triggerChan = jt.trigger.c
	}

	l.Debug("Starting timer job")
	jt.health.OK("Primed")

	stat := &spanstat.SpanStat{}

	for {
		select {
		case <-ctx.Done():
			jt.health.Stopped("timer job context done")
			return
		case <-timer.C:
		case <-triggerChan:
		}

		l.Debug("Timer job triggered")

		stat.Start()

		err := jt.fn(ctx)

		total := stat.End(true).Total()
		options.metrics.TimerRunDuration.WithLabelValues(jt.name).Observe(total.Seconds())
		stat.Reset()

		if err == nil {
			jt.health.OK("OK (" + total.String() + ")")
			l.Debug("Timer job finished")
		} else if !errors.Is(err, context.Canceled) {
			jt.health.Degraded("timer job errored", err)
			l.WithError(err).Error("Timer job errored")

			options.metrics.JobErrorsTotal.WithLabelValues(jt.name).Inc()
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

// AddObserver adds an observer job to the group. Observer jobs invoke the given `fn` for each item observed on
// `observable`. If the `observable` completes, the job stops. The context given to the observable is also canceled
// once the group stops.
func Observer[T any](name string, fn ObserverFunc[T], observable stream.Observable[T], opts ...observerOpt[T]) Job {
	if fn == nil {
		panic("`fn` must not be nil")
	}

	job := &jobObserver[T]{
		name:       name,
		fn:         fn,
		observable: observable,
		opts:       opts,
	}

	return job
}

// ObserverFunc is the func type invoked by observer jobs.
// A ObserverFunc is expected to return as soon as ctx is canceled.
type ObserverFunc[T any] func(ctx context.Context, event T) error

type observerOpt[T any] func(*jobObserver[T])

type jobObserver[T any] struct {
	name string
	fn   ObserverFunc[T]
	opts []observerOpt[T]

	health cell.HealthReporter

	observable stream.Observable[T]

	// If not nil, call the shutdowner on error
	shutdown hive.Shutdowner
}

func (jo *jobObserver[T]) start(ctx context.Context, wg *sync.WaitGroup, scope cell.Scope, options options) {
	defer wg.Done()

	for _, opt := range jo.opts {
		opt(jo)
	}

	jo.health = cell.GetHealthReporter(scope, "observer-job-"+jo.name)
	reportTicker := time.NewTicker(10 * time.Second)
	defer reportTicker.Stop()

	l := options.logger.WithFields(logrus.Fields{
		"name": jo.name,
		"func": internal.FuncNameAndLocation(jo.fn),
	})

	l.Debug("Observer job started")
	jo.health.OK("Primed")
	var msgCount uint64

	done := make(chan struct{})

	var (
		stat = &spanstat.SpanStat{}
		err  error
	)
	jo.observable.Observe(ctx, func(t T) {
		stat.Start()

		err := jo.fn(ctx, t)

		total := stat.End(true).Total()
		options.metrics.ObserverRunDuration.WithLabelValues(jo.name).Observe(total.Seconds())
		stat.Reset()

		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}

			jo.health.Degraded("observer job errored", err)
			l.WithError(err).Error("Observer job errored")
			options.metrics.JobErrorsTotal.WithLabelValues(jo.name).Inc()
			if jo.shutdown != nil {
				jo.shutdown.Shutdown(hive.ShutdownWithError(
					err,
				))
			}
			return
		}

		msgCount++

		// Don't report health for every event, only when we have not done so for a bit
		select {
		case <-reportTicker.C:
			jo.health.OK("OK (" + total.String() + ") [" + strconv.FormatUint(msgCount, 10) + "]")
		default:
		}
	}, func(e error) {
		err = e
		close(done)
	})

	<-done

	jo.health.Stopped("observer job done")
	if err != nil {
		l.WithError(err).Error("Observer job stopped with an error")
	} else {
		l.WithError(err).Debug("Observer job stopped")
	}
}
