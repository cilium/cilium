// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package job

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"runtime/pprof"
	"sync"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
)

// Cell provides job.Registry which constructs job.Group's. Job groups automate a lot of the logic involved with
// lifecycle management of goroutines within a Hive Cell. Providing a context that is canceled on shutdown and making
// sure multiple goroutines properly shutdown takes a lot of boilerplate. Job groups make it easy to queue, spawn, and
// collect jobs with minimal boilerplate. The registry maintains references to all groups which will allow us to add
// automatic metrics collection and/or status reporting in the future.
var Cell = cell.Module(
	"jobs",
	"Managed background goroutines and timers",
	cell.Provide(
		newRegistry,
	),
)

// A Registry creates Groups, it maintains references to these groups for the purposes of collecting information
// centralized like metrics.
type Registry interface {
	// NewGroup creates a new group of jobs which can be started and stopped together as part of the cells lifecycle.
	// The provided scope is used to report health status of the jobs. A `cell.Scope` can be obtained via injection
	// an object with the correct scope is provided by the closest `cell.Module`.
	NewGroup(health cell.Health, lc cell.Lifecycle, opts ...groupOpt) Group
}

type registry struct {
	logger     *slog.Logger
	shutdowner hive.Shutdowner

	mu     sync.Mutex
	groups []Group
}

func newRegistry(
	logger *slog.Logger,
	shutdowner hive.Shutdowner,
) Registry {
	return &registry{
		logger:     logger,
		shutdowner: shutdowner,
	}
}

// NewGroup creates a new Group with the given `opts` options, which allows you to customize the behavior for the
// group as a whole. For example by allowing you to add pprof labels to the group or by customizing the logger.
//
// Jobs added to the group before it is started will be appended to the provided lifecycle. Jobs added
// after starting are started immediately.
func (c *registry) NewGroup(health cell.Health, lc cell.Lifecycle, opts ...groupOpt) Group {
	c.mu.Lock()
	defer c.mu.Unlock()

	var options options
	options.logger = c.logger
	options.shutdowner = c.shutdowner

	for _, opt := range opts {
		opt(&options)
	}

	g := &group{
		options:   options,
		lifecycle: lc,
		wg:        &sync.WaitGroup{},
		health:    health,
	}
	// Append the lifecycle hooks for the group. The start hook sets up a context
	// for the dynamical jobs (jobs added after starting) and a stop hook to cancel
	// the context and wait for the jobs to finish.
	lc.Append((*groupHooks)(g))

	c.groups = append(c.groups, g)

	return g
}

// Group aims to streamline the management of work within a cell.
// A group allows you to add multiple types of jobs with different kinds of logic.
// No matter the job type, the function provided to is always called with a context which
// is bound to the lifecycle of the cell.
type Group interface {
	// Add append the job. If the group has not yet been started the job is queued, otherwise it is started
	// immediately.
	Add(...Job)

	// Scoped creates a scoped group, jobs added to this scoped group will appear as a sub-scope in the health reporter
	Scoped(name string) ScopedGroup
}

// Job in an interface that describes a unit of work which can be added to a Group. This interface contains unexported
// methods and thus can only be implemented by functions in this package such as OneShot, Timer, or Observer.
type Job interface {
	start(ctx context.Context, wg *sync.WaitGroup, health cell.Health, options options)
}

type queuedJob struct {
	job     Job
	health  cell.Health
	options options

	wq     sync.WaitGroup
	cancel context.CancelFunc
}

// Start implements cell.HookInterface.
func (qj *queuedJob) Start(cell.HookContext) error {
	qj.wq.Add(1)

	var ctx context.Context
	ctx, qj.cancel = context.WithCancel(context.Background())
	pprof.Do(ctx, qj.options.pprofLabels, func(ctx context.Context) {
		go qj.job.start(ctx, &qj.wq, qj.health, qj.options)
	})
	return nil
}

// Stop implements cell.HookInterface.
func (qj *queuedJob) Stop(ctx cell.HookContext) error {
	qj.cancel()

	stopped := make(chan struct{})
	go func() {
		qj.wq.Wait()
		close(stopped)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-stopped:
		return nil
	}
}

var _ cell.HookInterface = &queuedJob{}

type group struct {
	options   options
	lifecycle cell.Lifecycle

	// wg is a wait group for "dynamic" jobs added after starting.
	wg *sync.WaitGroup

	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc

	health cell.Health
}

type options struct {
	pprofLabels pprof.LabelSet
	logger      *slog.Logger
	shutdowner  hive.Shutdowner
	metrics     Metrics
}

type groupOpt func(o *options)

// WithLogger replaces the default logger with the given logger, useful if you want to add certain fields to the logs
// created by the group/jobs.
func WithLogger(logger *slog.Logger) groupOpt {
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

func WithMetrics(metrics Metrics) groupOpt {
	return func(o *options) {
		o.metrics = metrics
	}
}

var _ cell.HookInterface = (*groupHooks)(nil)

// groupHooks implements the Hive start and stop hooks. Hidden as these
// are appended by NewGroup.
type groupHooks group

// Start implements the cell.HookInterface interface
func (gh *groupHooks) Start(_ cell.HookContext) error {
	jg := (*group)(gh)
	jg.mu.Lock()
	defer jg.mu.Unlock()

	// Create a context for the dynamically started jobs.
	jg.ctx, jg.cancel = context.WithCancel(context.Background())
	return nil
}

// Stop implements the cell.HookInterface interface
func (gh *groupHooks) Stop(stopCtx cell.HookContext) error {
	jg := (*group)(gh)
	jg.mu.Lock()
	defer jg.mu.Unlock()

	// Stop all dynamically started jobs.
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
	jg.add(jg.health, jobs...)
}

func (jg *group) add(health cell.Health, jobs ...Job) {
	jg.mu.Lock()
	defer jg.mu.Unlock()

	// The context is only set once the group has been started.
	// If we have not yet started append hooks for the jobs to be started as part
	// of the normal lifecycle. This makes sure that the start order reflects the
	// order in which the jobs are added and avoids e.g. starting a job before its
	// dependencies.
	if jg.ctx == nil {
		for _, job := range jobs {
			jg.lifecycle.Append(&queuedJob{
				job:     job,
				health:  health,
				options: jg.options,
			})
		}
		return
	}

	for _, j := range jobs {
		jg.wg.Add(1)
		pprof.Do(jg.ctx, jg.options.pprofLabels, func(ctx context.Context) {
			go j.start(ctx, jg.wg, health, jg.options)
		})
	}
}

// Scoped creates a scoped group, jobs added to this scoped group will appear as a sub-scope in the health reporter
func (jg *group) Scoped(name string) ScopedGroup {
	return &scopedGroup{
		group:  jg,
		health: jg.health.NewScope(name),
	}
}

type ScopedGroup interface {
	Add(jobs ...Job)
}

type scopedGroup struct {
	group  *group
	health cell.Health
}

func (sg *scopedGroup) Add(jobs ...Job) {
	sg.group.add(sg.health, jobs...)
}

const maxNameLength = 100

func sanitizeName(name string) string {
	mangled := false
	newLength := min(maxNameLength, len(name))
	runes := make([]rune, 0, newLength)
	for _, r := range name[:newLength] {
		switch {
		case r >= 'a' && r <= 'z':
			fallthrough
		case r >= 'A' && r <= 'Z':
			fallthrough
		case r >= '0' && r <= '9':
			fallthrough
		case r == '-' || r == '_':
			runes = append(runes, r)
		default:
			// Skip invalid characters.
			mangled = true
		}
	}
	if mangled || len(name) > maxNameLength {
		// Name was mangled or is too long, truncate and append hash.
		const hashLen = 10
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(name)))
		newLen := min(maxNameLength-hashLen, len(runes))
		runes = runes[:newLen]
		return string(runes) + "-" + hash[:hashLen]
	}
	return string(runes)
}
