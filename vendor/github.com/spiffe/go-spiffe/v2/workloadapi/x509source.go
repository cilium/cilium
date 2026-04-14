package workloadapi

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// X509Source is a source of X509-SVIDs and X.509 bundles maintained via the
// Workload API.
type X509Source struct {
	watcher *watcher
	picker  func([]*x509svid.SVID) *x509svid.SVID

	mtx     sync.RWMutex
	svid    *x509svid.SVID
	bundles *x509bundle.Set

	closeMtx sync.RWMutex
	closed   bool
}

// NewX509Source creates a new X509Source. It blocks until the initial update
// has been received from the Workload API. The source should be closed when
// no longer in use to free underlying resources.
func NewX509Source(ctx context.Context, options ...X509SourceOption) (_ *X509Source, err error) {
	config := &x509SourceConfig{}
	for _, option := range options {
		option.configureX509Source(config)
	}

	s := &X509Source{
		picker: config.picker,
	}

	s.watcher, err = newWatcher(ctx, config.watcher, s.setX509Context, nil)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Close closes the source, dropping the connection to the Workload API.
// Other source methods will return an error after Close has been called.
// The underlying Workload API client will also be closed if it is owned by
// the X509Source (i.e. not provided via the WithClient option).
func (s *X509Source) Close() (err error) {
	s.closeMtx.Lock()
	s.closed = true
	s.closeMtx.Unlock()

	return s.watcher.Close()
}

// GetX509SVID returns an X509-SVID from the source. It implements the
// x509svid.Source interface.
func (s *X509Source) GetX509SVID() (*x509svid.SVID, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}

	s.mtx.RLock()
	svid := s.svid
	s.mtx.RUnlock()

	if svid == nil {
		// This is a defensive check and should be unreachable since the source
		// waits for the initial Workload API update before returning from
		// New().
		return nil, wrapX509sourceErr(errors.New("missing X509-SVID"))
	}
	return svid, nil
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the x509bundle.Source interface.
func (s *X509Source) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}

	return s.bundles.GetX509BundleForTrustDomain(trustDomain)
}

// WaitUntilUpdated waits until the source is updated or the context is done,
// in which case ctx.Err() is returned.
func (s *X509Source) WaitUntilUpdated(ctx context.Context) error {
	return s.watcher.WaitUntilUpdated(ctx)
}

// Updated returns a channel that is sent on whenever the source is updated.
func (s *X509Source) Updated() <-chan struct{} {
	return s.watcher.Updated()
}

func (s *X509Source) setX509Context(x509Context *X509Context) {
	var svid *x509svid.SVID
	if s.picker == nil {
		svid = x509Context.DefaultSVID()
	} else {
		svid = s.picker(x509Context.SVIDs)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.svid = svid
	s.bundles = x509Context.Bundles
}

func (s *X509Source) checkClosed() error {
	s.closeMtx.RLock()
	defer s.closeMtx.RUnlock()
	if s.closed {
		return wrapX509sourceErr(errors.New("source is closed"))
	}
	return nil
}

func wrapX509sourceErr(err error) error {
	return fmt.Errorf("x509source: %w", err)
}
