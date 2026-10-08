// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package job

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/cilium/stream"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/internal"
)

// Observer jobs invoke the given `fn` for each item observed on `observable`.
// The Observer name must match regex "^[a-zA-Z][a-zA-Z0-9_\-]{0,100}$". If the `observable` completes, the job stops.
// The context given to the observable is also canceled once the group stops.
func Observer[T any](name string, fn ObserverFunc[T], observable stream.Observable[T], opts ...observerOpt[T]) Job {
	name = sanitizeName(name)
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

// WithObserverShutdown option configures an observer job to shutdown the whole
// hive if the observer function returns a non-nil, non-context.Canceled error.
func WithObserverShutdown[T any]() observerOpt[T] {
	return func(jo *jobObserver[T]) {
		jo.shutdownOnError = true
	}
}

type jobObserver[T any] struct {
	name string
	fn   ObserverFunc[T]
	opts []observerOpt[T]

	health cell.Health

	observable stream.Observable[T]

	// If not nil, call the shutdowner on error
	shutdown        hive.Shutdowner
	shutdownOnError bool
}

func (jo *jobObserver[T]) info() string {
	return fmt.Sprintf("%s (%s)", jo.name, internal.FuncNameAndLocation(jo.fn))
}

func (jo *jobObserver[T]) start(ctx context.Context, health cell.Health, options options) {
	for _, opt := range jo.opts {
		opt(jo)
	}

	if jo.shutdownOnError && options.shutdowner != nil {
		jo.shutdown = options.shutdowner
	}

	jo.health = health.NewScope("observer-job-" + jo.name)
	defer jo.health.Close()
	reportTicker := time.NewTicker(10 * time.Second)
	defer reportTicker.Stop()

	l := options.logger.With(
		"name", jo.name,
		"func", internal.FuncNameAndLocation(jo.fn))

	jo.health.OK("Primed")
	var msgCount uint64

	done := make(chan struct{})

	var err error
	jo.observable.Observe(ctx, func(t T) {
		start := time.Now()
		err := jo.fn(ctx, t)
		duration := time.Since(start)

		if options.metrics != nil {
			options.metrics.ObserverRunDuration(jo.name, duration)
		}

		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}

			msg := fmt.Sprintf("Observer job failed (duration %s)", duration)
			jo.health.Degraded(msg, err)
			l.Error("Observer job errored",
				"error", err,
				"duration", duration,
			)

			if options.metrics != nil {
				options.metrics.JobError(jo.name, err)
			}
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
			jo.health.OK("OK (" + duration.String() + ") [" + strconv.FormatUint(msgCount, 10) + "]")
		default:
		}
	}, func(e error) {
		err = e
		close(done)
	})

	<-done

	if err != nil && !errors.Is(err, context.Canceled) {
		l.Error("Observer job stopped with an error", "error", err)
	}
}
