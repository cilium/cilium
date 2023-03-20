package workloadapi

import (
	"context"
	"sync"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/zeebo/errs"
)

type sourceClient interface {
	WatchX509Context(context.Context, X509ContextWatcher) error
	WatchJWTBundles(context.Context, JWTBundleWatcher) error
	FetchJWTSVID(context.Context, jwtsvid.Params) (*jwtsvid.SVID, error)
	FetchJWTSVIDs(context.Context, jwtsvid.Params) ([]*jwtsvid.SVID, error)
	Close() error
}

type watcherConfig struct {
	client        sourceClient
	clientOptions []ClientOption
}

type watcher struct {
	updatedCh chan struct{}

	client     sourceClient
	ownsClient bool

	cancel func()
	wg     sync.WaitGroup

	closeMtx sync.Mutex
	closed   bool
	closeErr error

	x509ContextFn      func(*X509Context)
	x509ContextSet     chan struct{}
	x509ContextSetOnce sync.Once

	jwtBundlesFn      func(*jwtbundle.Set)
	jwtBundlesSet     chan struct{}
	jwtBundlesSetOnce sync.Once
}

func newWatcher(ctx context.Context, config watcherConfig, x509ContextFn func(*X509Context), jwtBundlesFn func(*jwtbundle.Set)) (_ *watcher, err error) {
	w := &watcher{
		updatedCh:      make(chan struct{}, 1),
		client:         config.client,
		cancel:         func() {},
		x509ContextFn:  x509ContextFn,
		x509ContextSet: make(chan struct{}),
		jwtBundlesFn:   jwtBundlesFn,
		jwtBundlesSet:  make(chan struct{}),
	}

	// If this function fails, we need to clean up the source.
	defer func() {
		if err != nil {
			err = errs.Combine(err, w.Close())
		}
	}()

	// Initialize a new client unless one is provided by the options
	if w.client == nil {
		client, err := New(ctx, config.clientOptions...)
		if err != nil {
			return nil, err
		}
		w.client = client
		w.ownsClient = true
	}

	errCh := make(chan error, 2)
	waitFor := func(has <-chan struct{}) error {
		select {
		case <-has:
			return nil
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Kick up a background goroutine that watches the Workload API for
	// updates.
	var watchCtx context.Context
	watchCtx, w.cancel = context.WithCancel(context.Background())

	if w.x509ContextFn != nil {
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			errCh <- w.client.WatchX509Context(watchCtx, w)
		}()
		if err := waitFor(w.x509ContextSet); err != nil {
			return nil, err
		}
	}

	if w.jwtBundlesFn != nil {
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			errCh <- w.client.WatchJWTBundles(watchCtx, w)
		}()
		if err := waitFor(w.jwtBundlesSet); err != nil {
			return nil, err
		}
	}

	// Drain the update channel since this function blocks until an update and
	// don't want callers to think there was an update on the source right
	// after it was initialized. If we ever allow the watcher to be initialzed
	// without waiting, this reset should be removed.
	w.drainUpdated()

	return w, nil
}

// Close closes the watcher, dropping the connection to the Workload API.
func (w *watcher) Close() error {
	w.closeMtx.Lock()
	defer w.closeMtx.Unlock()

	if !w.closed {
		w.cancel()
		w.wg.Wait()

		// Close() can be called by New() to close a partially intialized source.
		// Only close the client if it has been set and the source owns it.
		if w.client != nil && w.ownsClient {
			w.closeErr = w.client.Close()
		}
		w.closed = true
	}
	return w.closeErr
}

func (w *watcher) OnX509ContextUpdate(x509Context *X509Context) {
	w.x509ContextFn(x509Context)
	w.x509ContextSetOnce.Do(func() {
		close(w.x509ContextSet)
	})
	w.triggerUpdated()
}

func (w *watcher) OnX509ContextWatchError(err error) {
	// The watcher doesn't do anything special with the error. If logging is
	// desired, it should be provided to the Workload API client.
}

func (w *watcher) OnJWTBundlesUpdate(jwtBundles *jwtbundle.Set) {
	w.jwtBundlesFn(jwtBundles)
	w.jwtBundlesSetOnce.Do(func() {
		close(w.jwtBundlesSet)
	})
	w.triggerUpdated()
}

func (w *watcher) OnJWTBundlesWatchError(error) {
	// The watcher doesn't do anything special with the error. If logging is
	// desired, it should be provided to the Workload API client.
}

func (w *watcher) WaitUntilUpdated(ctx context.Context) error {
	select {
	case <-w.updatedCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *watcher) Updated() <-chan struct{} {
	return w.updatedCh
}

func (w *watcher) drainUpdated() {
	select {
	case <-w.updatedCh:
	default:
	}
}

func (w *watcher) triggerUpdated() {
	w.drainUpdated()
	w.updatedCh <- struct{}{}
}
