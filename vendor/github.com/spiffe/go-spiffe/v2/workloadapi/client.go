package workloadapi

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Client is a Workload API client.
type Client struct {
	conn     *grpc.ClientConn
	wlClient workload.SpiffeWorkloadAPIClient
	config   clientConfig
}

// New dials the Workload API and returns a client. The client should be closed
// when no longer in use to free underlying resources.
func New(ctx context.Context, options ...ClientOption) (*Client, error) {
	c := &Client{
		config: defaultClientConfig(),
	}
	for _, opt := range options {
		opt.configureClient(&c.config)
	}

	err := c.setAddress()
	if err != nil {
		return nil, err
	}

	c.conn, err = c.newConn(ctx)
	if err != nil {
		return nil, err
	}

	c.wlClient = workload.NewSpiffeWorkloadAPIClient(c.conn)
	return c, nil
}

// Close closes the client.
func (c *Client) Close() error {
	return c.conn.Close()
}

// FetchX509SVID fetches the default X509-SVID, i.e. the first in the list
// returned by the Workload API.
func (c *Client) FetchX509SVID(ctx context.Context) (*x509svid.SVID, error) {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	stream, err := c.wlClient.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}

	svids, err := parseX509SVIDs(resp, true)
	if err != nil {
		return nil, err
	}

	return svids[0], nil
}

// FetchX509SVIDs fetches all X509-SVIDs.
func (c *Client) FetchX509SVIDs(ctx context.Context) ([]*x509svid.SVID, error) {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	stream, err := c.wlClient.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}

	return parseX509SVIDs(resp, false)
}

// FetchX509Bundles fetches the X.509 bundles.
func (c *Client) FetchX509Bundles(ctx context.Context) (*x509bundle.Set, error) {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	stream, err := c.wlClient.FetchX509Bundles(ctx, &workload.X509BundlesRequest{})
	if err != nil {
		return nil, err
	}
	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}

	return parseX509BundlesResponse(resp)
}

// WatchX509Bundles watches for changes to the X.509 bundles. The watcher receives
// the updated X.509 bundles.
func (c *Client) WatchX509Bundles(ctx context.Context, watcher X509BundleWatcher) error {
	backoff := c.config.backoffStrategy.NewBackoff()
	for {
		err := c.watchX509Bundles(ctx, watcher, backoff)
		watcher.OnX509BundlesWatchError(err)
		err = c.handleWatchError(ctx, err, backoff)
		if err != nil {
			return err
		}
	}
}

// FetchX509Context fetches the X.509 context, which contains both X509-SVIDs
// and X.509 bundles.
func (c *Client) FetchX509Context(ctx context.Context) (*X509Context, error) {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	stream, err := c.wlClient.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}

	return parseX509Context(resp)
}

// WatchX509Context watches for updates to the X.509 context. The watcher
// receives the updated X.509 context.
func (c *Client) WatchX509Context(ctx context.Context, watcher X509ContextWatcher) error {
	backoff := c.config.backoffStrategy.NewBackoff()
	for {
		err := c.watchX509Context(ctx, watcher, backoff)
		watcher.OnX509ContextWatchError(err)
		err = c.handleWatchError(ctx, err, backoff)
		if err != nil {
			return err
		}
	}
}

// FetchJWTSVID fetches a JWT-SVID.
func (c *Client) FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	audience := append([]string{params.Audience}, params.ExtraAudiences...)
	resp, err := c.wlClient.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{
		SpiffeId: params.Subject.String(),
		Audience: audience,
	})
	if err != nil {
		return nil, err
	}

	svids, err := parseJWTSVIDs(resp, audience, true)
	if err != nil {
		return nil, err
	}

	return svids[0], nil
}

// FetchJWTSVIDs fetches all JWT-SVIDs.
func (c *Client) FetchJWTSVIDs(ctx context.Context, params jwtsvid.Params) ([]*jwtsvid.SVID, error) {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	audience := append([]string{params.Audience}, params.ExtraAudiences...)
	resp, err := c.wlClient.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{
		SpiffeId: params.Subject.String(),
		Audience: audience,
	})
	if err != nil {
		return nil, err
	}

	return parseJWTSVIDs(resp, audience, false)
}

// FetchJWTBundles fetches the JWT bundles for JWT-SVID validation, keyed
// by a SPIFFE ID of the trust domain to which they belong.
func (c *Client) FetchJWTBundles(ctx context.Context) (*jwtbundle.Set, error) {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	stream, err := c.wlClient.FetchJWTBundles(ctx, &workload.JWTBundlesRequest{})
	if err != nil {
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}

	return parseJWTSVIDBundles(resp)
}

// WatchJWTBundles watches for changes to the JWT bundles. The watcher receives
// the updated JWT bundles.
func (c *Client) WatchJWTBundles(ctx context.Context, watcher JWTBundleWatcher) error {
	backoff := c.config.backoffStrategy.NewBackoff()
	for {
		err := c.watchJWTBundles(ctx, watcher, backoff)
		watcher.OnJWTBundlesWatchError(err)
		err = c.handleWatchError(ctx, err, backoff)
		if err != nil {
			return err
		}
	}
}

// ValidateJWTSVID validates the JWT-SVID token. The parsed and validated
// JWT-SVID is returned.
func (c *Client) ValidateJWTSVID(ctx context.Context, token, audience string) (*jwtsvid.SVID, error) {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	_, err := c.wlClient.ValidateJWTSVID(ctx, &workload.ValidateJWTSVIDRequest{
		Svid:     token,
		Audience: audience,
	})
	if err != nil {
		return nil, err
	}

	return jwtsvid.ParseInsecure(token, []string{audience})
}

// FetchWITSVID fetches the default WIT-SVID (i.e. the first in the list
// returned by the Workload API). An optional SPIFFE ID may be provided to
// request a specific WIT-SVID.
//
// Experimental: subject to change.
func (c *Client) FetchWITSVID(ctx context.Context, spiffeID string) (*witsvid.SVID, error) {
	svids, err := c.fetchWITSVIDs(ctx, spiffeID, true)
	if err != nil {
		return nil, err
	}
	return svids[0], nil
}

// FetchWITSVIDs fetches all WIT-SVIDs. An optional SPIFFE ID may be provided
// to request a specific WIT-SVID.
//
// Experimental: subject to change.
func (c *Client) FetchWITSVIDs(ctx context.Context, spiffeID string) ([]*witsvid.SVID, error) {
	return c.fetchWITSVIDs(ctx, spiffeID, false)
}

// WatchWITSVIDs watches for WIT-SVID updates. The watcher receives the updated
// WIT-SVIDs. The optional spiffeID filters updates to a specific identity.
//
// If the server returns codes.Unimplemented, the watch loop terminates without
// retrying per the SPIFFE Workload API spec §7 (WIT-SVID Profile).
//
// Experimental: subject to change.
func (c *Client) WatchWITSVIDs(ctx context.Context, watcher WITSVIDWatcher, spiffeID string) error {
	backoff := c.config.backoffStrategy.NewBackoff()
	for {
		err := c.watchWITSVIDs(ctx, watcher, backoff, spiffeID)
		watcher.OnWITSVIDsWatchError(err)
		if status.Code(err) == codes.Unimplemented {
			c.config.log.Errorf("WIT-SVID profile not supported by server: %v", err)
			return err
		}
		if err = c.handleWatchError(ctx, err, backoff); err != nil {
			return err
		}
	}
}

// FetchWITBundles fetches the WIT bundles for WIT-SVID validation, keyed by
// the SPIFFE ID of the trust domain to which they belong.
//
// Experimental: subject to change.
func (c *Client) FetchWITBundles(ctx context.Context) (*witbundle.Set, error) {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	stream, err := c.wlClient.FetchWITBundles(ctx, &workload.WITBundlesRequest{})
	if err != nil {
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}

	return parseWITBundles(resp)
}

// WatchWITBundles watches for changes to the WIT bundles. The watcher receives
// the updated WIT bundle set.
//
// If the server returns codes.Unimplemented, the watch loop terminates without
// retrying per the SPIFFE Workload API spec §7 (WIT-SVID Profile).
//
// Experimental: subject to change.
func (c *Client) WatchWITBundles(ctx context.Context, watcher WITBundleWatcher) error {
	backoff := c.config.backoffStrategy.NewBackoff()
	for {
		err := c.watchWITBundles(ctx, watcher, backoff)
		watcher.OnWITBundlesWatchError(err)
		if status.Code(err) == codes.Unimplemented {
			c.config.log.Errorf("WIT bundle profile not supported by server: %v", err)
			return err
		}
		if err = c.handleWatchError(ctx, err, backoff); err != nil {
			return err
		}
	}
}

func (c *Client) fetchWITSVIDs(ctx context.Context, spiffeID string, firstOnly bool) ([]*witsvid.SVID, error) {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	stream, err := c.wlClient.FetchWITSVID(ctx, &workload.WITSVIDRequest{
		SpiffeId: spiffeID,
	})
	if err != nil {
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}

	return parseWITSVIDs(resp, firstOnly)
}

func (c *Client) watchWITSVIDs(ctx context.Context, watcher WITSVIDWatcher, backoff Backoff, spiffeID string) error {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	c.config.log.Debugf("Watching WIT-SVIDs")
	stream, err := c.wlClient.FetchWITSVID(ctx, &workload.WITSVIDRequest{
		SpiffeId: spiffeID,
	})
	if err != nil {
		return err
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			return err
		}

		backoff.Reset()
		svids, err := parseWITSVIDs(resp, false)
		if err != nil {
			c.config.log.Errorf("Failed to parse WIT-SVID response: %v", err)
			watcher.OnWITSVIDsWatchError(err)
			continue
		}
		watcher.OnWITSVIDsUpdate(svids)
	}
}

func (c *Client) watchWITBundles(ctx context.Context, watcher WITBundleWatcher, backoff Backoff) error {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	c.config.log.Debugf("Watching WIT bundles")
	stream, err := c.wlClient.FetchWITBundles(ctx, &workload.WITBundlesRequest{})
	if err != nil {
		return err
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			return err
		}

		backoff.Reset()
		bundleSet, err := parseWITBundles(resp)
		if err != nil {
			c.config.log.Errorf("Failed to parse WIT bundle response: %v", err)
			watcher.OnWITBundlesWatchError(err)
			continue
		}
		watcher.OnWITBundlesUpdate(bundleSet)
	}
}

func parseWITSVIDs(resp *workload.WITSVIDResponse, firstOnly bool) ([]*witsvid.SVID, error) {
	n := len(resp.Svids)
	if n == 0 {
		return nil, errors.New("no WIT-SVIDs in response")
	}
	if firstOnly {
		n = 1
	}

	hints := make(map[string]struct{}, n)
	svids := make([]*witsvid.SVID, 0, n)
	for i := range n {
		s := resp.Svids[i]
		// In the event of more than one WITSVID with the same hint value set,
		// the first message in the list SHOULD be selected.
		if _, ok := hints[s.Hint]; ok && s.Hint != "" {
			continue
		}
		hints[s.Hint] = struct{}{}

		if s.WitSvidKey == "" {
			return nil, fmt.Errorf("missing private key for SVID with SPIFFE ID %q", s.SpiffeId)
		}

		svid, err := witsvid.ParseInsecure(s.WitSvid)
		if err != nil {
			return nil, err
		}

		privKey, err := parseJWKPrivateKey(s.WitSvidKey)
		if err != nil {
			return nil, err
		}
		svid.PrivateKey = privKey

		svid.Hint = s.Hint
		svids = append(svids, svid)
	}

	return svids, nil
}

func parseWITBundles(resp *workload.WITBundlesResponse) (*witbundle.Set, error) {
	bundles := make([]*witbundle.Bundle, 0, len(resp.Bundles))

	for tdID, bundleStr := range resp.Bundles {
		td, err := spiffeid.TrustDomainFromString(tdID)
		if err != nil {
			return nil, err
		}

		b, err := witbundle.Parse(td, []byte(bundleStr))
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, b)
	}

	return witbundle.NewSet(bundles...), nil
}

func parseJWKPrivateKey(jwkStr string) (any, error) {
	var jwkKey jose.JSONWebKey
	if err := jwkKey.UnmarshalJSON([]byte(jwkStr)); err != nil {
		return nil, fmt.Errorf("unable to parse private key JWK: %w", err)
	}
	if jwkKey.IsPublic() {
		return nil, errors.New("expected private key JWK, got public key")
	}
	return jwkKey.Key, nil
}

// WITSVIDWatcher receives WIT-SVID updates from the Workload API.
//
// Experimental: subject to change.
type WITSVIDWatcher interface {
	// OnWITSVIDsUpdate is called with the latest WIT-SVIDs retrieved from
	// the Workload API.
	OnWITSVIDsUpdate([]*witsvid.SVID)

	// OnWITSVIDsWatchError is called when there is a problem establishing
	// or maintaining connectivity with the Workload API.
	OnWITSVIDsWatchError(error)
}

// WITBundleWatcher receives WIT bundle updates from the Workload API.
//
// Experimental: subject to change.
type WITBundleWatcher interface {
	// OnWITBundlesUpdate is called with the latest WIT bundle set retrieved
	// from the Workload API.
	OnWITBundlesUpdate(*witbundle.Set)

	// OnWITBundlesWatchError is called when there is a problem establishing
	// or maintaining connectivity with the Workload API.
	OnWITBundlesWatchError(error)
}

func (c *Client) newConn(ctx context.Context) (*grpc.ClientConn, error) {
	c.config.dialOptions = append(c.config.dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	c.appendDialOptionsOS()
	return grpc.DialContext(ctx, c.config.address, c.config.dialOptions...) //nolint:staticcheck // preserve backcompat with WithDialOptions option
}

func (c *Client) handleWatchError(ctx context.Context, err error, backoff Backoff) error {
	code := status.Code(err)
	if code == codes.Canceled {
		return err
	}

	if code == codes.InvalidArgument {
		c.config.log.Errorf("Canceling watch: %v", err)
		return err
	}

	c.config.log.Errorf("Failed to watch the Workload API: %v", err)
	retryAfter := backoff.Next()
	c.config.log.Debugf("Retrying watch in %s", retryAfter)
	select {
	case <-time.After(retryAfter):
		return nil

	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) watchX509Context(ctx context.Context, watcher X509ContextWatcher, backoff Backoff) error {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	c.config.log.Debugf("Watching X.509 contexts")
	stream, err := c.wlClient.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		return err
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			return err
		}

		backoff.Reset()
		x509Context, err := parseX509Context(resp)
		if err != nil {
			c.config.log.Errorf("Failed to parse X509-SVID response: %v", err)
			watcher.OnX509ContextWatchError(err)
			continue
		}
		watcher.OnX509ContextUpdate(x509Context)
	}
}

func (c *Client) watchJWTBundles(ctx context.Context, watcher JWTBundleWatcher, backoff Backoff) error {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	c.config.log.Debugf("Watching JWT bundles")
	stream, err := c.wlClient.FetchJWTBundles(ctx, &workload.JWTBundlesRequest{})
	if err != nil {
		return err
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			return err
		}

		backoff.Reset()
		jwtbundleSet, err := parseJWTSVIDBundles(resp)
		if err != nil {
			c.config.log.Errorf("Failed to parse JWT bundle response: %v", err)
			watcher.OnJWTBundlesWatchError(err)
			continue
		}
		watcher.OnJWTBundlesUpdate(jwtbundleSet)
	}
}

func (c *Client) watchX509Bundles(ctx context.Context, watcher X509BundleWatcher, backoff Backoff) error {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	c.config.log.Debugf("Watching X.509 bundles")
	stream, err := c.wlClient.FetchX509Bundles(ctx, &workload.X509BundlesRequest{})
	if err != nil {
		return err
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			return err
		}

		backoff.Reset()
		x509bundleSet, err := parseX509BundlesResponse(resp)
		if err != nil {
			c.config.log.Errorf("Failed to parse X.509 bundle response: %v", err)
			watcher.OnX509BundlesWatchError(err)
			continue
		}
		watcher.OnX509BundlesUpdate(x509bundleSet)
	}
}

// X509ContextWatcher receives X509Context updates from the Workload API.
type X509ContextWatcher interface {
	// OnX509ContextUpdate is called with the latest X.509 context retrieved
	// from the Workload API.
	OnX509ContextUpdate(*X509Context)

	// OnX509ContextWatchError is called when there is a problem establishing
	// or maintaining connectivity with the Workload API.
	OnX509ContextWatchError(error)
}

// JWTBundleWatcher receives JWT bundle updates from the Workload API.
type JWTBundleWatcher interface {
	// OnJWTBundlesUpdate is called with the latest JWT bundle set retrieved
	// from the Workload API.
	OnJWTBundlesUpdate(*jwtbundle.Set)

	// OnJWTBundlesWatchError is called when there is a problem establishing
	// or maintaining connectivity with the Workload API.
	OnJWTBundlesWatchError(error)
}

// X509BundleWatcher receives X.509 bundle updates from the Workload API.
type X509BundleWatcher interface {
	// OnX509BundlesUpdate is called with the latest X.509 bundle set retrieved
	// from the Workload API.
	OnX509BundlesUpdate(*x509bundle.Set)

	// OnX509BundlesWatchError is called when there is a problem establishing
	// or maintaining connectivity with the Workload API.
	OnX509BundlesWatchError(error)
}

func withHeader(ctx context.Context) context.Context {
	header := metadata.Pairs("workload.spiffe.io", "true")
	return metadata.NewOutgoingContext(ctx, header)
}

func defaultClientConfig() clientConfig {
	return clientConfig{
		log:             logger.Null,
		backoffStrategy: defaultBackoffStrategy{},
	}
}

func parseX509Context(resp *workload.X509SVIDResponse) (*X509Context, error) {
	svids, err := parseX509SVIDs(resp, false)
	if err != nil {
		return nil, err
	}

	bundles, err := parseX509Bundles(resp)
	if err != nil {
		return nil, err
	}

	return &X509Context{
		SVIDs:   svids,
		Bundles: bundles,
	}, nil
}

// parseX509SVIDs parses one or all of the SVIDs in the response. If firstOnly
// is true, then only the first SVID in the response is parsed and returned.
// Otherwise, all SVIDs are parsed and returned.
func parseX509SVIDs(resp *workload.X509SVIDResponse, firstOnly bool) ([]*x509svid.SVID, error) {
	n := len(resp.Svids)
	if n == 0 {
		return nil, errors.New("no SVIDs in response")
	}
	if firstOnly {
		n = 1
	}

	hints := make(map[string]struct{}, n)
	svids := make([]*x509svid.SVID, 0, n)
	for i := 0; i < n; i++ {
		svid := resp.Svids[i]
		// In the event of more than one X509SVID message with the same hint value set, then the first message in the
		// list SHOULD be selected.
		if _, ok := hints[svid.Hint]; ok && svid.Hint != "" {
			continue
		}

		hints[svid.Hint] = struct{}{}

		s, err := x509svid.ParseRaw(svid.X509Svid, svid.X509SvidKey)
		if err != nil {
			return nil, err
		}
		s.Hint = svid.Hint
		svids = append(svids, s)
	}

	return svids, nil
}

func parseX509Bundles(resp *workload.X509SVIDResponse) (*x509bundle.Set, error) {
	bundles := []*x509bundle.Bundle{}
	for _, svid := range resp.Svids {
		b, err := parseX509Bundle(svid.SpiffeId, svid.Bundle)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, b)
	}

	for tdID, bundle := range resp.FederatedBundles {
		b, err := parseX509Bundle(tdID, bundle)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, b)
	}

	return x509bundle.NewSet(bundles...), nil
}

func parseX509Bundle(spiffeID string, bundle []byte) (*x509bundle.Bundle, error) {
	td, err := spiffeid.TrustDomainFromString(spiffeID)
	if err != nil {
		return nil, err
	}
	certs, err := x509.ParseCertificates(bundle)
	if err != nil {
		return nil, err
	}
	return x509bundle.FromX509Authorities(td, certs), nil
}

func parseX509BundlesResponse(resp *workload.X509BundlesResponse) (*x509bundle.Set, error) {
	bundles := []*x509bundle.Bundle{}

	for tdID, b := range resp.Bundles {
		td, err := spiffeid.TrustDomainFromString(tdID)
		if err != nil {
			return nil, err
		}

		b, err := x509bundle.ParseRaw(td, b)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, b)
	}

	return x509bundle.NewSet(bundles...), nil
}

// parseJWTSVIDs parses one or all of the SVIDs in the response. If firstOnly
// is true, then only the first SVID in the response is parsed and returned.
// Otherwise, all SVIDs are parsed and returned.
func parseJWTSVIDs(resp *workload.JWTSVIDResponse, audience []string, firstOnly bool) ([]*jwtsvid.SVID, error) {
	n := len(resp.Svids)
	if n == 0 {
		return nil, errors.New("there were no SVIDs in the response")
	}
	if firstOnly {
		n = 1
	}

	hints := make(map[string]struct{}, n)
	svids := make([]*jwtsvid.SVID, 0, n)
	for i := 0; i < n; i++ {
		svid := resp.Svids[i]
		// In the event of more than one X509SVID message with the same hint value set, then the first message in the
		// list SHOULD be selected.
		if _, ok := hints[svid.Hint]; ok && svid.Hint != "" {
			continue
		}
		hints[svid.Hint] = struct{}{}

		s, err := jwtsvid.ParseInsecure(svid.Svid, audience)
		if err != nil {
			return nil, err
		}
		s.Hint = svid.Hint
		svids = append(svids, s)
	}

	return svids, nil
}

func parseJWTSVIDBundles(resp *workload.JWTBundlesResponse) (*jwtbundle.Set, error) {
	bundles := []*jwtbundle.Bundle{}

	for tdID, b := range resp.Bundles {
		td, err := spiffeid.TrustDomainFromString(tdID)
		if err != nil {
			return nil, err
		}

		b, err := jwtbundle.Parse(td, b)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, b)
	}

	return jwtbundle.NewSet(bundles...), nil
}
