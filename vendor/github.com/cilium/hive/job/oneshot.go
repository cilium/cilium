// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package job

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/internal"
)

// OneShot creates a "one shot" job which can be added to a Group.
// The OneShot job name must match regex "^[a-zA-Z][a-zA-Z0-9_\-]{0,100}$". The function passed is invoked once at startup.
// It can live for the entire lifetime of the group or exit early depending on its task.
// If it returns an error, it can optionally be retried if the WithRetry option. If retries are not configured or
// all retries failed as well, a shutdown of the hive can be triggered by specifying the WithShutdown option.
//
// The given function is expected to exit as soon as the context given to it expires, this is especially important for
// blocking or long running jobs.
func OneShot(name string, fn OneShotFunc, opts ...jobOneShotOpt) Job {
	name = sanitizeName(name)
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

type RetryBackoff interface {
	Wait() time.Duration
}

type ConstantBackoff time.Duration

func (d ConstantBackoff) Wait() time.Duration {
	return time.Duration(d)
}

type ExponentialBackoff struct {
	Min     time.Duration
	Max     time.Duration
	current time.Duration
}

func (e *ExponentialBackoff) Wait() time.Duration {
	if e.current == 0 {
		e.current = e.Min
	} else {
		e.current *= 2
		if e.current > e.Max {
			e.current = e.Max
		}
	}
	return e.current
}

// WithRetry option configures a one shot job to retry `times` amount of times. On each retry attempt the
// rate limiter is waited upon before making another attempt.
// If `times` is <0, then the job is retried forever.
func WithRetry(times int, backoff RetryBackoff) jobOneShotOpt {
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

// OneShotFunc is the function type which is invoked by a one shot job. The given function is expected to exit as soon
// as the context given to it expires, this is especially important for blocking or long running jobs.
type OneShotFunc func(ctx context.Context, health cell.Health) error

type jobOneShot struct {
	name string
	fn   OneShotFunc
	opts []jobOneShotOpt

	health cell.Health

	// If retry > 0, retry on error x times.
	retry           int
	backoff         RetryBackoff
	shutdownOnError bool
}

func (jos *jobOneShot) info() string {
	return fmt.Sprintf("%s (%s)", jos.name, internal.FuncNameAndLocation(jos.fn))
}

func (jos *jobOneShot) start(ctx context.Context, health cell.Health, options options) {
	for _, opt := range jos.opts {
		opt(jos)
	}

	jos.health = health.NewScope("job-" + jos.name)
	defer jos.health.Close()

	l := options.logger.With(
		"name", jos.name,
		"func", internal.FuncNameAndLocation(jos.fn))

	var err error
	var timeout time.Duration
	for i := 0; jos.retry < 0 || i <= jos.retry; i++ {
		if i != 0 {
			options.logger.Debug("Delaying retry attempt",
				"backoff", timeout,
				"retry-count", i,
			)
			select {
			case <-ctx.Done():
				return
			case <-time.After(timeout):
			}
		}

		jos.health.OK("Running")
		start := time.Now()
		err = jos.fn(ctx, jos.health)

		duration := time.Since(start)
		if options.metrics != nil {
			options.metrics.OneShotRunDuration(jos.name, duration)
		}

		switch {
		case err == nil:
			jos.health.OK("Finished (" + duration.String() + ")")
			return
		case errors.Is(err, context.Canceled) || ctx.Err() != nil:
			return
		default:
			if jos.backoff != nil && (jos.retry < 0 || i < jos.retry) {
				timeout = jos.backoff.Wait()
			}
			retriesRemain := strconv.FormatInt(int64(jos.retry-i), 10)
			if jos.retry < 0 {
				retriesRemain = "<inf>"
			} else if jos.retry == 0 {
				retriesRemain = "<none>"
			}
			msg := fmt.Sprintf("Failed (duration %s, retry %d/%s in %s)", duration, i+1, retriesRemain, timeout)
			jos.health.Degraded(msg, err)
			l.Error("Failed",
				"error", err,
				"retry", i+1,
				"remaining", retriesRemain,
				"timeout", timeout,
				"duration", duration,
			)
			if options.metrics != nil {
				options.metrics.JobError(jos.name, err)
			}
		}
	}

	if options.shutdowner != nil && jos.shutdownOnError {
		options.shutdowner.Shutdown(hive.ShutdownWithError(err))
	}
}
