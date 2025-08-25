package workloadapi

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// BundleSource is a source of SPIFFE bundles maintained via the Workload API.
type BundleSource struct {
	watcher *watcher

	mtx             sync.RWMutex
	x509Authorities map[spiffeid.TrustDomain][]*x509.Certificate
	jwtAuthorities  map[spiffeid.TrustDomain]map[string]crypto.PublicKey

	closeMtx sync.RWMutex
	closed   bool
}

// NewBundleSource creates a new BundleSource. It blocks until the initial
// update has been received from the Workload API. The source should be closed
// when no longer in use to free underlying resources.
func NewBundleSource(ctx context.Context, options ...BundleSourceOption) (_ *BundleSource, err error) {
	config := &bundleSourceConfig{}
	for _, option := range options {
		option.configureBundleSource(config)
	}

	s := &BundleSource{
		x509Authorities: make(map[spiffeid.TrustDomain][]*x509.Certificate),
		jwtAuthorities:  make(map[spiffeid.TrustDomain]map[string]crypto.PublicKey),
	}

	s.watcher, err = newWatcher(ctx, config.watcher, s.setX509Context, s.setJWTBundles)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Close closes the source, dropping the connection to the Workload API.
// Other source methods will return an error after Close has been called.
// The underlying Workload API client will also be closed if it is owned by
// the BundleSource (i.e. not provided via the WithClient option).
func (s *BundleSource) Close() error {
	s.closeMtx.Lock()
	s.closed = true
	s.closeMtx.Unlock()

	return s.watcher.Close()
}

// GetBundleForTrustDomain returns the SPIFFE bundle for the given trust
// domain. It implements the spiffebundle.Source interface.
func (s *BundleSource) GetBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*spiffebundle.Bundle, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	x509Authorities, hasX509Authorities := s.x509Authorities[trustDomain]
	jwtAuthorities, hasJWTAuthorities := s.jwtAuthorities[trustDomain]
	if !hasX509Authorities && !hasJWTAuthorities {
		return nil, wrapBundlesourceErr(fmt.Errorf("no SPIFFE bundle for trust domain %q", trustDomain))
	}
	bundle := spiffebundle.New(trustDomain)
	if hasX509Authorities {
		bundle.SetX509Authorities(x509Authorities)
	}
	if hasJWTAuthorities {
		bundle.SetJWTAuthorities(jwtAuthorities)
	}
	return bundle, nil
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the x509bundle.Source interface.
func (s *BundleSource) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	x509Authorities, hasX509Authorities := s.x509Authorities[trustDomain]
	if !hasX509Authorities {
		return nil, wrapBundlesourceErr(fmt.Errorf("no X.509 bundle for trust domain %q", trustDomain))
	}
	return x509bundle.FromX509Authorities(trustDomain, x509Authorities), nil
}

// GetJWTBundleForTrustDomain returns the JWT bundle for the given trust
// domain. It implements the jwtbundle.Source interface.
func (s *BundleSource) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	jwtAuthorities, hasJWTAuthorities := s.jwtAuthorities[trustDomain]
	if !hasJWTAuthorities {
		return nil, wrapBundlesourceErr(fmt.Errorf("no JWT bundle for trust domain %q", trustDomain))
	}
	return jwtbundle.FromJWTAuthorities(trustDomain, jwtAuthorities), nil
}

// WaitUntilUpdated waits until the source is updated or the context is done,
// in which case ctx.Err() is returned.
func (s *BundleSource) WaitUntilUpdated(ctx context.Context) error {
	return s.watcher.WaitUntilUpdated(ctx)
}

// Updated returns a channel that is sent on whenever the source is updated.
func (s *BundleSource) Updated() <-chan struct{} {
	return s.watcher.Updated()
}

func (s *BundleSource) setX509Context(x509Context *X509Context) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	newBundles := x509Context.Bundles.Bundles()

	// Add/replace the X.509 authorities from the X.509 context. Track the trust
	// domains represented in the new X.509 context so we can determine which
	// existing trust domains are no longer represented.
	trustDomains := make(map[spiffeid.TrustDomain]struct{}, len(newBundles))
	for _, newBundle := range newBundles {
		trustDomains[newBundle.TrustDomain()] = struct{}{}
		s.x509Authorities[newBundle.TrustDomain()] = newBundle.X509Authorities()
	}

	// Remove the X.509 authority entries for trust domains no longer
	// represented in the X.509 context.
	for existingTD := range s.x509Authorities {
		if _, ok := trustDomains[existingTD]; ok {
			continue
		}
		delete(s.x509Authorities, existingTD)
	}
}

func (s *BundleSource) setJWTBundles(bundles *jwtbundle.Set) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	newBundles := bundles.Bundles()

	// Add/replace the JWT authorities from the JWT bundles. Track the trust
	// domains represented in the new JWT bundles so we can determine which
	// existing trust domains are no longer represented.
	trustDomains := make(map[spiffeid.TrustDomain]struct{}, len(newBundles))
	for _, newBundle := range newBundles {
		trustDomains[newBundle.TrustDomain()] = struct{}{}
		s.jwtAuthorities[newBundle.TrustDomain()] = newBundle.JWTAuthorities()
	}

	// Remove the JWT authority entries for trust domains no longer represented
	// in the JWT bundles.
	for existingTD := range s.jwtAuthorities {
		if _, ok := trustDomains[existingTD]; ok {
			continue
		}
		delete(s.jwtAuthorities, existingTD)
	}
}

func (s *BundleSource) checkClosed() error {
	s.closeMtx.RLock()
	defer s.closeMtx.RUnlock()
	if s.closed {
		return wrapBundlesourceErr(errors.New("source is closed"))
	}
	return nil
}

func wrapBundlesourceErr(err error) error {
	return fmt.Errorf("bundlesource: %w", err)
}
