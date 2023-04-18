package internal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// Kind is used to provide a source of events originating inside the cluster from Watches (e.g. Pod Create).
type Kind struct {
	// Type is the type of object to watch.  e.g. &v1.Pod{}
	Type client.Object

	// Cache used to watch APIs
	Cache cache.Cache

	// started may contain an error if one was encountered during startup. If its closed and does not
	// contain an error, startup and syncing finished.
	started     chan error
	startCancel func()
}

// Start is internal and should be called only by the Controller to register an EventHandler with the Informer
// to enqueue reconcile.Requests.
func (ks *Kind) Start(ctx context.Context, handler handler.EventHandler, queue workqueue.RateLimitingInterface,
	prct ...predicate.Predicate) error {
	if ks.Type == nil {
		return fmt.Errorf("must create Kind with a non-nil object")
	}
	if ks.Cache == nil {
		return fmt.Errorf("must create Kind with a non-nil cache")
	}

	// cache.GetInformer will block until its context is cancelled if the cache was already started and it can not
	// sync that informer (most commonly due to RBAC issues).
	ctx, ks.startCancel = context.WithCancel(ctx)
	ks.started = make(chan error)
	go func() {
		var (
			i       cache.Informer
			lastErr error
		)

		// Tries to get an informer until it returns true,
		// an error or the specified context is cancelled or expired.
		if err := wait.PollUntilContextCancel(ctx, 10*time.Second, true, func(ctx context.Context) (bool, error) {
			// Lookup the Informer from the Cache and add an EventHandler which populates the Queue
			i, lastErr = ks.Cache.GetInformer(ctx, ks.Type)
			if lastErr != nil {
				kindMatchErr := &meta.NoKindMatchError{}
				switch {
				case errors.As(lastErr, &kindMatchErr):
					log.Error(lastErr, "if kind is a CRD, it should be installed before calling Start",
						"kind", kindMatchErr.GroupKind)
				case runtime.IsNotRegisteredError(lastErr):
					log.Error(lastErr, "kind must be registered to the Scheme")
				default:
					log.Error(lastErr, "failed to get informer from cache")
				}
				return false, nil // Retry.
			}
			return true, nil
		}); err != nil {
			if lastErr != nil {
				ks.started <- fmt.Errorf("failed to get informer from cache: %w", lastErr)
				return
			}
			ks.started <- err
			return
		}

		_, err := i.AddEventHandler(NewEventHandler(ctx, queue, handler, prct).HandlerFuncs())
		if err != nil {
			ks.started <- err
			return
		}
		if !ks.Cache.WaitForCacheSync(ctx) {
			// Would be great to return something more informative here
			ks.started <- errors.New("cache did not sync")
		}
		close(ks.started)
	}()

	return nil
}

func (ks *Kind) String() string {
	if ks.Type != nil {
		return fmt.Sprintf("kind source: %T", ks.Type)
	}
	return "kind source: unknown type"
}

// WaitForSync implements SyncingSource to allow controllers to wait with starting
// workers until the cache is synced.
func (ks *Kind) WaitForSync(ctx context.Context) error {
	select {
	case err := <-ks.started:
		return err
	case <-ctx.Done():
		ks.startCancel()
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil
		}
		return fmt.Errorf("timed out waiting for cache to be synced for Kind %T", ks.Type)
	}
}
