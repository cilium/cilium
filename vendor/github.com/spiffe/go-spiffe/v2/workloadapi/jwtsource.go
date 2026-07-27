package workloadapi

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

// JWTSource is a source of JWT-SVID and JWT bundles maintained via the
// Workload API.
type JWTSource struct {
	watcher *watcher
	picker  func([]*jwtsvid.SVID) *jwtsvid.SVID

	mtx     sync.RWMutex
	bundles *jwtbundle.Set

	closeMtx sync.RWMutex
	closed   bool
}

// NewJWTSource creates a new JWTSource. It blocks until the initial update
// has been received from the Workload API. The source should be closed when
// no longer in use to free underlying resources.
func NewJWTSource(ctx context.Context, options ...JWTSourceOption) (_ *JWTSource, err error) {
	config := &jwtSourceConfig{}
	for _, option := range options {
		option.configureJWTSource(config)
	}

	s := &JWTSource{
		picker: config.picker,
	}

	s.watcher, err = newWatcher(ctx, config.watcher, nil, s.setJWTBundles)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Close closes the source, dropping the connection to the Workload API.
// Other source methods will return an error after Close has been called.
// The underlying Workload API client will also be closed if it is owned by
// the JWTSource (i.e. not provided via the WithClient option).
func (s *JWTSource) Close() error {
	s.closeMtx.Lock()
	s.closed = true
	s.closeMtx.Unlock()

	return s.watcher.Close()
}

// FetchJWTSVID fetches a JWT-SVID from the source with the given parameters.
// It implements the jwtsvid.Source interface.
func (s *JWTSource) FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}

	var (
		svid *jwtsvid.SVID
		err  error
	)
	if s.picker == nil {
		svid, err = s.watcher.client.FetchJWTSVID(ctx, params)
	} else {
		svids, err := s.watcher.client.FetchJWTSVIDs(ctx, params)
		if err != nil {
			return svid, err
		}
		svid = s.picker(svids)
	}

	return svid, err
}

// FetchJWTSVIDs fetches all JWT-SVIDs from the source with the given parameters.
// It implements the jwtsvid.Source interface.
func (s *JWTSource) FetchJWTSVIDs(ctx context.Context, params jwtsvid.Params) ([]*jwtsvid.SVID, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	return s.watcher.client.FetchJWTSVIDs(ctx, params)
}

// GetJWTBundleForTrustDomain returns the JWT bundle for the given trust
// domain. It implements the jwtbundle.Source interface.
func (s *JWTSource) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	return s.bundles.GetJWTBundleForTrustDomain(trustDomain)
}

// WaitUntilUpdated waits until the source is updated or the context is done,
// in which case ctx.Err() is returned.
func (s *JWTSource) WaitUntilUpdated(ctx context.Context) error {
	return s.watcher.WaitUntilUpdated(ctx)
}

// Updated returns a channel that is sent on whenever the source is updated.
func (s *JWTSource) Updated() <-chan struct{} {
	return s.watcher.Updated()
}

func (s *JWTSource) setJWTBundles(bundles *jwtbundle.Set) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.bundles = bundles
}

func (s *JWTSource) checkClosed() error {
	s.closeMtx.RLock()
	defer s.closeMtx.RUnlock()
	if s.closed {
		return wrapJwtsourceErr(errors.New("source is closed"))
	}
	return nil
}

func wrapJwtsourceErr(err error) error {
	return fmt.Errorf("jwtsource: %w", err)
}
