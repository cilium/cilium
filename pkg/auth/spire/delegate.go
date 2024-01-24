// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spire

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	spiffeTypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/cilium/pkg/auth/certs"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/time"
)

type SpireDelegateClient struct {
	cfg SpireDelegateConfig
	log logrus.FieldLogger

	connectionAttempts int

	stream      delegatedidentityv1.DelegatedIdentity_SubscribeToX509SVIDsClient
	trustStream delegatedidentityv1.DelegatedIdentity_SubscribeToX509BundlesClient

	svidStore      map[string]*delegatedidentityv1.X509SVIDWithKey
	svidStoreMutex lock.RWMutex
	trustBundle    *x509.CertPool

	cancelListenForUpdates context.CancelFunc

	rotatedIdentitiesChan chan certs.CertificateRotationEvent

	logLimiter logging.Limiter

	connected        bool
	lastConnectError error
	connectedMutex   lock.RWMutex
}

type SpireDelegateConfig struct {
	SpireAdminSocketPath string `mapstructure:"mesh-auth-spire-admin-socket"`
	SpiffeTrustDomain    string `mapstructure:"mesh-auth-spiffe-trust-domain"`
	RotatedQueueSize     int    `mapstructure:"mesh-auth-rotated-identities-queue-size"`
}

var Cell = cell.Module(
	"spire-delegate",
	"Spire Delegate API Client",
	cell.Provide(newSpireDelegateClient),
	cell.Config(SpireDelegateConfig{}),
)

func newSpireDelegateClient(lc cell.Lifecycle, cfg SpireDelegateConfig, log logrus.FieldLogger) certs.CertificateProvider {
	if cfg.SpireAdminSocketPath == "" {
		log.Info("Spire Delegate API Client is disabled as no socket path is configured")
		return nil
	}
	client := &SpireDelegateClient{
		cfg:                   cfg,
		log:                   log,
		svidStore:             map[string]*delegatedidentityv1.X509SVIDWithKey{},
		rotatedIdentitiesChan: make(chan certs.CertificateRotationEvent, cfg.RotatedQueueSize),
		logLimiter:            logging.NewLimiter(10*time.Second, 3),
	}

	lc.Append(cell.Hook{OnStart: client.onStart, OnStop: client.onStop})

	return client
}

func (cfg SpireDelegateConfig) Flags(flags *pflag.FlagSet) {
	flags.StringVar(&cfg.SpireAdminSocketPath, "mesh-auth-spire-admin-socket", "", "The path for the SPIRE admin agent Unix socket.") // default is /run/spire/sockets/admin.sock
	flags.StringVar(&cfg.SpiffeTrustDomain, "mesh-auth-spiffe-trust-domain", "spiffe.cilium", "The trust domain for the SPIFFE identity.")
	flags.IntVar(&cfg.RotatedQueueSize, "mesh-auth-rotated-identities-queue-size", 1024, "The size of the queue for signaling rotated identities.")
}

func (s *SpireDelegateClient) onStart(ctx cell.HookContext) error {
	s.log.Info("Spire Delegate API Client is running")

	listenCtx, cancel := context.WithCancel(context.Background())
	go s.listenForUpdates(listenCtx)

	s.cancelListenForUpdates = cancel

	return nil
}

func (s *SpireDelegateClient) onStop(ctx cell.HookContext) error {
	s.log.Info("SPIFFE Delegate API Client is stopping")

	s.cancelListenForUpdates()

	if s.stream != nil {
		s.stream.CloseSend()
	}

	return nil
}

func (s *SpireDelegateClient) listenForUpdates(ctx context.Context) {
	s.openStream(ctx)

	listenCtx, cancel := context.WithCancel(ctx)
	err := make(chan error)

	go s.listenForSVIDUpdates(listenCtx, err)
	go s.listenForBundleUpdates(listenCtx, err)

	backoffTime := backoff.Exponential{Min: 100 * time.Millisecond, Max: 10 * time.Second}
	for {
		select {
		case <-ctx.Done():
			cancel()
			return
		case e := <-err:
			s.log.WithError(e).Error("Error in delegate stream, restarting")
			time.Sleep(backoffTime.Duration(s.connectionAttempts))
			cancel()
			s.connectionAttempts++
			s.listenForUpdates(ctx)
			return
		}
	}
}

func (s *SpireDelegateClient) listenForSVIDUpdates(ctx context.Context, errorChan chan error) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			resp, err := s.stream.Recv()
			if err != nil {
				errorChan <- err
				return
			}

			s.log.
				WithField("nr_of_svids", len(resp.X509Svids)).
				Debug("Received X509-SVID update")
			s.handleX509SVIDUpdate(resp.X509Svids)
		}
	}
}

func (s *SpireDelegateClient) listenForBundleUpdates(ctx context.Context, errorChan chan error) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			resp, err := s.trustStream.Recv()
			if err != nil {
				errorChan <- err
				return
			}

			s.log.
				WithField("nr_of_bundles", len(resp.CaCertificates)).
				Debug("Received X509-Bundle update", len(resp.CaCertificates))
			s.handleX509BundleUpdate(resp.CaCertificates)
		}
	}
}

func (s *SpireDelegateClient) handleX509SVIDUpdate(svids []*delegatedidentityv1.X509SVIDWithKey) {
	newSvidStore := map[string]*delegatedidentityv1.X509SVIDWithKey{}

	s.svidStoreMutex.RLock()
	updatedKeys := []string{}
	deletedKeys := []string{}

	for _, svid := range svids {

		if svid.X509Svid.Id.TrustDomain != s.cfg.SpiffeTrustDomain {
			s.log.
				WithField("trust_domain", svid.X509Svid.Id.TrustDomain).
				Debug("Skipping X509-SVID update as it does not match ours")
			s.svidStoreMutex.RUnlock()
			return
		}

		key := fmt.Sprintf("spiffe://%s%s", svid.X509Svid.Id.TrustDomain, svid.X509Svid.Id.Path)

		if _, exists := s.svidStore[key]; exists {
			old := s.svidStore[key]
			if old.X509Svid.ExpiresAt != svid.X509Svid.ExpiresAt || !equalCertChains(old.X509Svid.CertChain, svid.X509Svid.CertChain) {
				updatedKeys = append(updatedKeys, key)
			}
		} else {
			s.log.
				WithField("spiffe_id", key).
				Debug("Adding newly discovered X509-SVID")
		}
		newSvidStore[key] = svid

	}

	// check for deleted keys
	for key := range s.svidStore {
		if _, exists := newSvidStore[key]; !exists {
			deletedKeys = append(deletedKeys, key)
		}
	}

	s.svidStoreMutex.RUnlock()

	s.svidStoreMutex.Lock()
	s.svidStore = newSvidStore
	s.svidStoreMutex.Unlock()

	for _, key := range deletedKeys {
		// we send an update event to re-trigger a handshake if needed
		id, err := s.spiffeIDToNumericIdentity(key)
		if err != nil {
			s.log.
				WithError(err).
				WithField("spiffe_id", key).
				Error("Failed to convert SPIFFE ID to numeric identity")
			continue
		}
		select {
		case s.rotatedIdentitiesChan <- certs.CertificateRotationEvent{Identity: id, Deleted: true}:
			s.log.
				WithField("spiffe_id", key).
				Debug("X509-SVID has been deleted, signaling this")
		default:
			if s.logLimiter.Allow() {
				s.log.
					WithField("identity", id).
					Warn("Skip sending deleted identity as channel is full")
			}
		}
	}

	for _, key := range updatedKeys {
		// we send an update event to re-trigger a handshake if needed
		id, err := s.spiffeIDToNumericIdentity(key)
		if err != nil {
			s.log.
				WithError(err).
				WithField("spiffe_id", key).
				Error("Failed to convert SPIFFE ID to numeric identity")
			continue
		}
		select {
		case s.rotatedIdentitiesChan <- certs.CertificateRotationEvent{Identity: id}:
			s.log.
				WithField("spiffe_id", key).
				Debug("X509-SVID has changed, signaling this")
		default:
			if s.logLimiter.Allow() {
				s.log.
					WithField("identity", id).
					Warn("Skip sending rotated identity as channel is full")
			}
		}
	}
}

func (s *SpireDelegateClient) handleX509BundleUpdate(bundles map[string][]byte) {
	pool := x509.NewCertPool()

	for trustDomain, bundle := range bundles {
		s.log.
			WithField("trust_domain", trustDomain).
			Debug("Processing trust domain cert bundle", trustDomain)

		certs, err := x509.ParseCertificates(bundle)
		if err != nil {
			s.log.
				WithError(err).
				WithField("trust_domain", trustDomain).
				Error("Failed to parse X.509 DER bundle")
			continue
		}

		for _, cert := range certs {
			pool.AddCert(cert)
		}
	}

	s.trustBundle = pool
}

func (s *SpireDelegateClient) openStream(ctx context.Context) {
	// try to init the watcher with a backoff
	backoffTime := backoff.Exponential{Min: 100 * time.Millisecond, Max: 10 * time.Second}

	// a retry might have happened, signal that we are disconnected
	s.connectedMutex.Lock()
	s.connected = false
	s.connectedMutex.Unlock()

	for {
		s.log.Info("Connecting to SPIRE Delegate API Client")

		var err error
		s.stream, s.trustStream, err = s.initWatcher(ctx)
		if err != nil {
			s.log.WithError(err).Warn("SPIRE Delegate API Client failed to init watcher, retrying")

			s.connectedMutex.Lock()
			s.connected = false
			s.lastConnectError = err
			s.connectedMutex.Unlock()

			time.Sleep(backoffTime.Duration(s.connectionAttempts))
			s.connectionAttempts++
			continue
		}

		s.connectedMutex.Lock()
		s.connected = true
		s.lastConnectError = nil
		s.connectedMutex.Unlock()
		break
	}
}

func (s *SpireDelegateClient) initWatcher(ctx context.Context) (delegatedidentityv1.DelegatedIdentity_SubscribeToX509SVIDsClient, delegatedidentityv1.DelegatedIdentity_SubscribeToX509BundlesClient, error) {
	if _, err := os.Stat(s.cfg.SpireAdminSocketPath); errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("SPIRE admin socket (%s) does not exist: %w", s.cfg.SpireAdminSocketPath, err)
	}

	unixPath := fmt.Sprintf("unix://%s", s.cfg.SpireAdminSocketPath)

	conn, err := grpc.Dial(unixPath, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(20*1024*1024),
			grpc.MaxCallSendMsgSize(20*1024*1024))) // setting this to 20MB to handle large bundles TODO: improve this once fixed upstream (https://github.com/cilium/cilium/issues/24297)
	if err != nil {
		return nil, nil, fmt.Errorf("grpc.Dial() failed on %s: %w", unixPath, err)
	}

	client := delegatedidentityv1.NewDelegatedIdentityClient(conn)

	stream, err := client.SubscribeToX509SVIDs(ctx, &delegatedidentityv1.SubscribeToX509SVIDsRequest{
		Selectors: []*spiffeTypes.Selector{
			{
				Type:  "cilium",
				Value: "mutual-auth",
			},
		},
	})

	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("stream failed on %s: %w", unixPath, err)
	}

	trustStream, err := client.SubscribeToX509Bundles(ctx, &delegatedidentityv1.SubscribeToX509BundlesRequest{})
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("stream for x509 bundle failed on %s: %w", unixPath, err)
	}

	return stream, trustStream, nil
}

func equalCertChains(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
