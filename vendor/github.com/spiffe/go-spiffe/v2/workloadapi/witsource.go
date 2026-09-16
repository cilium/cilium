package workloadapi

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// WITSource is a source of WIT-SVIDs and WIT bundles maintained via the
// Workload API. It implements both witsvid.Source and witbundle.Source.
//
// Experimental: subject to change.
type WITSource struct {
	watcherBase

	client     *Client
	ownsClient bool

	mtx     sync.RWMutex
	svids   []*witsvid.SVID
	bundles *witbundle.Set

	svidsSet       chan struct{}
	svidsSetOnce   sync.Once
	bundlesSet     chan struct{}
	bundlesSetOnce sync.Once
}

// NewWITSource creates a new WITSource. It blocks until the initial updates
// have been received from the Workload API. The source should be closed when
// no longer in use to free underlying resources.
//
// Experimental: subject to change.
func NewWITSource(ctx context.Context, options ...WITSourceOption) (_ *WITSource, err error) {
	config := &witSourceConfig{}
	for _, option := range options {
		option.configureWITSource(config)
	}

	var client *Client
	var ownsClient bool
	if config.client != nil {
		client = config.client
	} else {
		client, err = New(ctx, config.clientOptions...)
		if err != nil {
			return nil, err
		}
		ownsClient = true
	}

	s := &WITSource{
		watcherBase: newWatcherBase(),
		client:      client,
		ownsClient:  ownsClient,
		bundles:     witbundle.NewSet(),
		svidsSet:    make(chan struct{}),
		bundlesSet:  make(chan struct{}),
	}

	defer func() {
		if err != nil {
			err = errors.Join(err, s.Close())
		}
	}()

	if err := s.waitForInitial(ctx); err != nil {
		return nil, err
	}
	s.drainUpdated()
	return s, nil
}

func (s *WITSource) waitForInitial(ctx context.Context) error {
	errCh := make(chan error, 2)

	var watchCtx context.Context
	watchCtx, s.cancel = context.WithCancel(context.Background())

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		errCh <- s.client.WatchWITSVIDs(watchCtx, s, "")
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		errCh <- s.client.WatchWITBundles(watchCtx, s)
	}()

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

	if err := waitFor(s.svidsSet); err != nil {
		return err
	}
	if err := waitFor(s.bundlesSet); err != nil {
		return err
	}
	return nil
}

// Close closes the source, dropping the connection to the Workload API.
//
// Experimental: subject to change.
func (s *WITSource) Close() error {
	var closer func() error
	if s.ownsClient && s.client != nil {
		closer = s.client.Close
	}
	return s.closeBase(closer)
}

// GetWITSVIDForID returns the WIT-SVID for the given SPIFFE ID.
// It implements the witsvid.Source interface.
//
// Experimental: subject to change.
func (s *WITSource) GetWITSVIDForID(id spiffeid.ID) (*witsvid.SVID, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}

	s.mtx.RLock()
	defer s.mtx.RUnlock()

	for _, svid := range s.svids {
		if svid.ID == id {
			return svid, nil
		}
	}
	return nil, fmt.Errorf("witsource: no WIT-SVID found for SPIFFE ID %q", id)
}

// GetWITBundleForTrustDomain returns the WIT bundle for the given trust domain.
// It implements the witbundle.Source interface.
//
// Experimental: subject to change.
func (s *WITSource) GetWITBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*witbundle.Bundle, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}

	s.mtx.RLock()
	defer s.mtx.RUnlock()

	return s.bundles.GetWITBundleForTrustDomain(trustDomain)
}

// WaitUntilUpdated waits until the source is updated or the context is done,
// in which case ctx.Err() is returned.
//
// Experimental: subject to change.
func (s *WITSource) WaitUntilUpdated(ctx context.Context) error {
	return s.waitUntilUpdated(ctx)
}

// Updated returns a channel that is sent on whenever the source is updated.
//
// Experimental: subject to change.
func (s *WITSource) Updated() <-chan struct{} {
	return s.updated()
}

// OnWITSVIDsUpdate implements WITSVIDWatcher.
func (s *WITSource) OnWITSVIDsUpdate(svids []*witsvid.SVID) {
	s.mtx.Lock()
	s.svids = svids
	s.mtx.Unlock()

	s.triggerUpdated()
	s.svidsSetOnce.Do(func() { close(s.svidsSet) })
}

// OnWITSVIDsWatchError implements WITSVIDWatcher.
func (s *WITSource) OnWITSVIDsWatchError(error) {
	// The watcher doesn't do anything special with the error. If logging is
	// desired, it should be provided to the Workload API client.
}

// OnWITBundlesUpdate implements WITBundleWatcher.
func (s *WITSource) OnWITBundlesUpdate(bundles *witbundle.Set) {
	s.mtx.Lock()
	s.bundles = bundles
	s.mtx.Unlock()

	s.triggerUpdated()
	s.bundlesSetOnce.Do(func() { close(s.bundlesSet) })
}

// OnWITBundlesWatchError implements WITBundleWatcher.
func (s *WITSource) OnWITBundlesWatchError(error) {
	// The watcher doesn't do anything special with the error. If logging is
	// desired, it should be provided to the Workload API client.
}

func (s *WITSource) checkClosed() error {
	s.closeMtx.Lock()
	defer s.closeMtx.Unlock()
	if s.closed {
		return errors.New("witsource: source is closed")
	}
	return nil
}
