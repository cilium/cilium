package internal

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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
type Kind[T client.Object] struct {
	// Type is the type of object to watch.  e.g. &v1.Pod{}
	Type T

	// Cache used to watch APIs
	Cache cache.Cache

	Handler handler.TypedEventHandler[T]

	Predicates []predicate.TypedPredicate[T]

	// startedErr may contain an error if one was encountered during startup. If its closed and does not
	// contain an error, startup and syncing finished.
	startedErr  chan error
	startCancel func()
}

// Start is internal and should be called only by the Controller to register an EventHandler with the Informer
// to enqueue reconcile.Requests.
func (ks *Kind[T]) Start(ctx context.Context, queue workqueue.RateLimitingInterface) error {
	if isNil(ks.Type) {
		return fmt.Errorf("must create Kind with a non-nil object")
	}
	if isNil(ks.Cache) {
		return fmt.Errorf("must create Kind with a non-nil cache")
	}
	if isNil(ks.Handler) {
		return errors.New("must create Kind with non-nil handler")
	}

	// cache.GetInformer will block until its context is cancelled if the cache was already started and it can not
	// sync that informer (most commonly due to RBAC issues).
	ctx, ks.startCancel = context.WithCancel(ctx)
	ks.startedErr = make(chan error)
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
				ks.startedErr <- fmt.Errorf("failed to get informer from cache: %w", lastErr)
				return
			}
			ks.startedErr <- err
			return
		}

		_, err := i.AddEventHandler(NewEventHandler(ctx, queue, ks.Handler, ks.Predicates).HandlerFuncs())
		if err != nil {
			ks.startedErr <- err
			return
		}
		if !ks.Cache.WaitForCacheSync(ctx) {
			// Would be great to return something more informative here
			ks.startedErr <- errors.New("cache did not sync")
		}
		close(ks.startedErr)
	}()

	return nil
}

func (ks *Kind[T]) String() string {
	if !isNil(ks.Type) {
		return fmt.Sprintf("kind source: %T", ks.Type)
	}
	return "kind source: unknown type"
}

// WaitForSync implements SyncingSource to allow controllers to wait with starting
// workers until the cache is synced.
func (ks *Kind[T]) WaitForSync(ctx context.Context) error {
	select {
	case err := <-ks.startedErr:
		return err
	case <-ctx.Done():
		ks.startCancel()
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil
		}
		return fmt.Errorf("timed out waiting for cache to be synced for Kind %T", ks.Type)
	}
}

func isNil(arg any) bool {
	if v := reflect.ValueOf(arg); !v.IsValid() || ((v.Kind() == reflect.Ptr ||
		v.Kind() == reflect.Interface ||
		v.Kind() == reflect.Slice ||
		v.Kind() == reflect.Map ||
		v.Kind() == reflect.Chan ||
		v.Kind() == reflect.Func) && v.IsNil()) {
		return true
	}
	return false
}
