// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package job

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/internal"
	"github.com/cilium/stream"
)

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

	health cell.Health

	observable stream.Observable[T]

	// If not nil, call the shutdowner on error
	shutdown hive.Shutdowner
}

func (jo *jobObserver[T]) start(ctx context.Context, wg *sync.WaitGroup, health cell.Health, options options) {
	defer wg.Done()

	for _, opt := range jo.opts {
		opt(jo)
	}

	jo.health = health.NewScope("observer-job-" + jo.name)
	reportTicker := time.NewTicker(10 * time.Second)
	defer reportTicker.Stop()

	l := options.logger.With(
		"name", jo.name,
		"func", internal.FuncNameAndLocation(jo.fn))

	l.Debug("Observer job started")
	jo.health.OK("Primed")
	var msgCount uint64

	done := make(chan struct{})

	var (
		err error
	)
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

			jo.health.Degraded("observer job errored", err)
			l.Error("Observer job errored", "error", err)

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

	jo.health.Stopped("observer job done")
	if err != nil {
		l.Error("Observer job stopped with an error", "error", err)
	} else {
		l.Debug("Observer job stopped")
	}
}
