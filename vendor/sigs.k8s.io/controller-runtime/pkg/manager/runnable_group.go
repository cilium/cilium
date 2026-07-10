package manager

import (
	"context"
	"errors"
	"sync"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

var (
	errRunnableGroupStopped = errors.New("can't accept new runnable as stop procedure is already engaged")
)

// readyRunnable encapsulates a runnable with
// a ready check.
type readyRunnable struct {
	Runnable
	Check       runnableCheck
	signalReady bool
}

// runnableCheck can be passed to Add() to let the runnable group determine that a
// runnable is ready. A runnable check should block until a runnable is ready,
// if the returned result is false, the runnable is considered not ready and failed.
type runnableCheck func(ctx context.Context) bool

// runnables handles all the runnables for a manager by grouping them accordingly to their
// type (webhooks, caches etc.).
type runnables struct {
	HTTPServers    *runnableGroup
	Webhooks       *runnableGroup
	Caches         *runnableGroup
	LeaderElection *runnableGroup
	Warmup         *runnableGroup
	Others         *runnableGroup
}

// newRunnables creates a new runnables object.
func newRunnables(baseContext BaseContextFunc, errChan chan error) *runnables {
	return &runnables{
		HTTPServers:    newRunnableGroup(baseContext, errChan),
		Webhooks:       newRunnableGroup(baseContext, errChan),
		Caches:         newRunnableGroup(baseContext, errChan),
		LeaderElection: newRunnableGroup(baseContext, errChan),
		Warmup:         newRunnableGroup(baseContext, errChan),
		Others:         newRunnableGroup(baseContext, errChan),
	}
}

// withLogger returns the runnables with the logger set for all runnable groups.
func (r *runnables) withLogger(logger logr.Logger) *runnables {
	r.HTTPServers.withLogger(logger)
	r.Webhooks.withLogger(logger)
	r.Caches.withLogger(logger)
	r.LeaderElection.withLogger(logger)
	r.Others.withLogger(logger)
	return r
}

// Add adds a runnable to closest group of runnable that they belong to.
//
// Add should be able to be called before and after Start, but not after StopAndWait.
// Add should return an error when called during StopAndWait.
// The runnables added before Start are started when Start is called.
// The runnables added after Start are started directly.
func (r *runnables) Add(fn Runnable) error {
	switch runnable := fn.(type) {
	case *Server:
		if runnable.NeedLeaderElection() {
			return r.LeaderElection.Add(fn, nil)
		}
		return r.HTTPServers.Add(fn, nil)
	case hasCache:
		return r.Caches.Add(fn, func(ctx context.Context) bool {
			return runnable.GetCache().WaitForCacheSync(ctx)
		})
	case webhook.Server:
		return r.Webhooks.Add(fn, nil)
	case warmupRunnable, LeaderElectionRunnable:
		if warmupRunnable, ok := fn.(warmupRunnable); ok {
			if err := r.Warmup.Add(RunnableFunc(warmupRunnable.Warmup), nil); err != nil {
				return err
			}
		}

		leaderElectionRunnable, ok := fn.(LeaderElectionRunnable)
		if !ok {
			// If the runnable is not a LeaderElectionRunnable, add it to the leader election group for backwards compatibility
			return r.LeaderElection.Add(fn, nil)
		}

		if !leaderElectionRunnable.NeedLeaderElection() {
			return r.Others.Add(fn, nil)
		}
		return r.LeaderElection.Add(fn, nil)
	default:
		return r.LeaderElection.Add(fn, nil)
	}
}

// runnableGroup manages a group of runnables that are
// meant to be running together until StopAndWait is called.
//
// Runnables can be added to a group after the group has started
// but not after it's stopped or while shutting down.
type runnableGroup struct {
	ctx    context.Context
	cancel context.CancelFunc

	start        sync.Mutex
	startOnce    sync.Once
	started      bool
	startQueue   []*readyRunnable
	startReadyCh chan *readyRunnable

	stop     sync.RWMutex
	stopOnce sync.Once
	stopped  bool

	// errChan is the error channel passed by the caller
	// when the group is created.
	// All errors are forwarded to this channel once they occur.
	errChan chan error

	// ch is the internal channel where the runnables are read off from.
	ch chan *readyRunnable

	// wg is an internal sync.WaitGroup that allows us to properly stop
	// and wait for all the runnables to finish before returning.
	wg *sync.WaitGroup

	// logger is used for logging when errors are dropped during shutdown
	logger logr.Logger
}

func newRunnableGroup(baseContext BaseContextFunc, errChan chan error) *runnableGroup {
	r := &runnableGroup{
		startReadyCh: make(chan *readyRunnable),
		errChan:      errChan,
		ch:           make(chan *readyRunnable),
		wg:           new(sync.WaitGroup),
		logger:       logr.Discard(), // Default to no-op logger
	}

	r.ctx, r.cancel = context.WithCancel(baseContext())
	return r
}

// withLogger sets the logger for this runnable group.
func (r *runnableGroup) withLogger(logger logr.Logger) {
	r.logger = logger
}

// Started returns true if the group has started.
func (r *runnableGroup) Started() bool {
	r.start.Lock()
	defer r.start.Unlock()
	return r.started
}

// Start starts the group and waits for all
// initially registered runnables to start.
// It can only be called once, subsequent calls have no effect.
func (r *runnableGroup) Start(ctx context.Context) error {
	var retErr error

	r.startOnce.Do(func() {
		defer close(r.startReadyCh)

		// Start the internal reconciler.
		go r.reconcile()

		// Start the group and queue up all
		// the runnables that were added prior.
		r.start.Lock()
		r.started = true
		for _, rn := range r.startQueue {
			rn.signalReady = true
			r.ch <- rn
		}
		r.start.Unlock()

		// If we don't have any queue, return.
		if len(r.startQueue) == 0 {
			return
		}

		// Wait for all runnables to signal.
		for {
			select {
			case <-ctx.Done():
				if err := ctx.Err(); !errors.Is(err, context.Canceled) {
					retErr = err
				}
			case rn := <-r.startReadyCh:
				for i, existing := range r.startQueue {
					if existing == rn {
						// Remove the item from the start queue.
						r.startQueue = append(r.startQueue[:i], r.startQueue[i+1:]...)
						break
					}
				}
				// We're done waiting if the queue is empty, return.
				if len(r.startQueue) == 0 {
					return
				}
			}
		}
	})

	return retErr
}

// reconcile is our main entrypoint for every runnable added
// to this group. Its primary job is to read off the internal channel
// and schedule runnables while tracking their state.
func (r *runnableGroup) reconcile() {
	for runnable := range r.ch {
		// Handle stop.
		// If the shutdown has been called we want to avoid
		// adding new goroutines to the WaitGroup because Wait()
		// panics if Add() is called after it.
		{
			r.stop.RLock()
			if r.stopped {
				// Drop any runnables if we're stopped.
				r.errChan <- errRunnableGroupStopped
				r.stop.RUnlock()
				continue
			}

			// Why is this here?
			// When StopAndWait is called, if a runnable is in the process
			// of being added, we could end up in a situation where
			// the WaitGroup is incremented while StopAndWait has called Wait(),
			// which would result in a panic.
			r.wg.Add(1)
			r.stop.RUnlock()
		}

		// Start the runnable.
		go func(rn *readyRunnable) {
			go func() {
				if rn.Check(r.ctx) {
					if rn.signalReady {
						r.startReadyCh <- rn
					}
				}
			}()

			// If we return, the runnable ended cleanly
			// or returned an error to the channel.
			//
			// We should always decrement the WaitGroup here.
			defer r.wg.Done()

			// Start the runnable.
			if err := rn.Start(r.ctx); err != nil {
				// Check if we're during the shutdown process.
				r.stop.RLock()
				isStopped := r.stopped
				r.stop.RUnlock()

				if isStopped {
					// During shutdown, try to send error first (error drain goroutine might still be running)
					// but drop if it would block to prevent goroutine leaks
					select {
					case r.errChan <- err:
						// Error sent successfully (error drain goroutine is still running)
					default:
						// Error drain goroutine has exited, drop error to prevent goroutine leak
						if !errors.Is(err, context.Canceled) { // don't log context.Canceled errors as they are expected during shutdown
							r.logger.Info("error dropped during shutdown to prevent goroutine leak", "error", err)
						}
					}
				} else {
					// During normal operation, always try to send errors (may block briefly)
					r.errChan <- err
				}
			}
		}(runnable)
	}
}

// Add should be able to be called before and after Start, but not after StopAndWait.
// Add should return an error when called during StopAndWait.
func (r *runnableGroup) Add(rn Runnable, ready runnableCheck) error {
	r.stop.RLock()
	if r.stopped {
		r.stop.RUnlock()
		return errRunnableGroupStopped
	}
	r.stop.RUnlock()

	if ready == nil {
		ready = func(_ context.Context) bool { return true }
	}

	readyRunnable := &readyRunnable{
		Runnable: rn,
		Check:    ready,
	}

	// Handle start.
	// If the overall runnable group isn't started yet
	// we want to buffer the runnables and let Start()
	// queue them up again later.
	{
		r.start.Lock()

		// Check if we're already started.
		if !r.started {
			// Store the runnable in the internal if not.
			r.startQueue = append(r.startQueue, readyRunnable)
			r.start.Unlock()
			return nil
		}
		r.start.Unlock()
	}

	// Recheck if we're stopped and hold the readlock, given that the stop and start can be called
	// at the same time, we can end up in a situation where the runnable is added
	// after the group is stopped and the channel is closed.
	r.stop.RLock()
	defer r.stop.RUnlock()
	if r.stopped {
		return errRunnableGroupStopped
	}

	// Enqueue the runnable.
	r.ch <- readyRunnable
	return nil
}

// StopAndWait waits for all the runnables to finish before returning.
func (r *runnableGroup) StopAndWait(ctx context.Context) {
	r.stopOnce.Do(func() {
		// Close the reconciler channel once we're done.
		defer func() {
			r.stop.Lock()
			close(r.ch)
			r.stop.Unlock()
		}()

		_ = r.Start(ctx)
		r.stop.Lock()
		// Store the stopped variable so we don't accept any new
		// runnables for the time being.
		r.stopped = true
		r.stop.Unlock()

		// Cancel the internal channel.
		r.cancel()

		done := make(chan struct{})
		go func() {
			defer close(done)
			// Wait for all the runnables to finish.
			r.wg.Wait()
		}()

		select {
		case <-done:
			// We're done, exit.
		case <-ctx.Done():
			// Calling context has expired, exit.
		}
	})
}
