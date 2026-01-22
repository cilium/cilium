// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/auth/certs"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/time"
	zconfig "github.com/cilium/cilium/pkg/ztunnel/config"
)

type endpointGetter interface {
	GetEndpoints() []*endpoint.Endpoint
}

type mutualAuthParams struct {
	cell.In

	CertificateProvider certs.CertificateProvider

	EndpointManager endpointmanager.EndpointManager
}

func newMutualAuthHandler(logger *slog.Logger, lc cell.Lifecycle, cfg MutualAuthConfig, params mutualAuthParams, zcfg zconfig.Config) authHandlerResult {
	if cfg.MutualAuthListenerPort == 0 || zcfg.EnableZTunnel {
		logger.Info("Mutual authentication handler is disabled as no port is configured")
		return authHandlerResult{}
	}
	if params.CertificateProvider == nil {
		logger.Error("No certificate provider configured, but one is required. Please check if the spire flags are configured.")
		os.Exit(1)
	}

	mAuthHandler := &mutualAuthHandler{
		cfg:             cfg,
		log:             logger,
		cert:            params.CertificateProvider,
		endpointManager: params.EndpointManager,
	}

	lc.Append(cell.Hook{OnStart: mAuthHandler.onStart, OnStop: mAuthHandler.onStop})

	return authHandlerResult{
		AuthHandler: mAuthHandler,
	}
}

type MutualAuthConfig struct {
	MutualAuthListenerPort   int           `mapstructure:"mesh-auth-mutual-listener-port"`
	MutualAuthConnectTimeout time.Duration `mapstructure:"mesh-auth-mutual-connect-timeout"`
}

func (cfg MutualAuthConfig) Flags(flags *pflag.FlagSet) {
	flags.IntVar(&cfg.MutualAuthListenerPort, "mesh-auth-mutual-listener-port", 0,
		"Port on which the Cilium Agent will perform mutual authentication handshakes between other Agents")
	flags.DurationVar(&cfg.MutualAuthConnectTimeout, "mesh-auth-mutual-connect-timeout", 5*time.Second,
		"Timeout for connecting to the remote node TCP socket")
}

type mutualAuthHandler struct {
	cell.In

	cfg MutualAuthConfig
	log *slog.Logger

	cert certs.CertificateProvider

	cancelSocketListen context.CancelFunc

	endpointManager endpointGetter
}

func (m *mutualAuthHandler) authenticate(ar *authRequest) (*authResponse, error) {
	if ar == nil {
		return nil, errors.New("authRequest is nil")
	}
	clientCert, err := m.cert.GetCertificateForIdentity(ar.localIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate for local identity %s: %w", ar.localIdentity.String(), err)
	}

	caBundle, err := m.cert.GetTrustBundle()
	if err != nil {
		return nil, fmt.Errorf("failed to get CA bundle: %w", err)
	}

	// set up TCP connection
	conn, err := net.DialTimeout("tcp",
		net.JoinHostPort(ar.remoteNodeIP, strconv.Itoa(m.cfg.MutualAuthListenerPort)),
		m.cfg.MutualAuthConnectTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s:%d: %w", ar.remoteNodeIP, m.cfg.MutualAuthListenerPort, err)
	}
	defer conn.Close()

	var expirationTime = &clientCert.Leaf.NotAfter

	// set up TLS socket

	//nolint:gosec // InsecureSkipVerify is not insecure as we do the verification in VerifyPeerCertificate
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: m.cert.NumericIdentityToSNI(ar.remoteIdentity),
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return clientCert, nil
		},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // not insecure as we do the verification in VerifyPeerCertificate
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// verifiedChains will be nil as we set InsecureSkipVerify to true

			chain := make([]*x509.Certificate, len(rawCerts))
			for i, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return fmt.Errorf("failed to parse certificate: %w", err)
				}
				chain[i] = cert
			}

			peerExpirationTime, err := m.verifyPeerCertificate(&ar.remoteIdentity, caBundle, [][]*x509.Certificate{chain})
			if peerExpirationTime != nil && peerExpirationTime.Before(*expirationTime) {
				expirationTime = peerExpirationTime // send down the lowest expiration time of the two certificates
			}
			return err
		},
		ClientCAs: caBundle,
		RootCAs:   caBundle,
	})
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("failed to perform TLS handshake: %w", err)
	}

	if expirationTime == nil {
		return nil, fmt.Errorf("failed to get expiration time of peer certificate")
	}

	return &authResponse{
		expirationTime: *expirationTime,
	}, nil
}

func (m *mutualAuthHandler) authType() policyTypes.AuthType {
	return policyTypes.AuthTypeSpire
}

func (m *mutualAuthHandler) listenForConnections(upstreamCtx context.Context, ready chan<- struct{}) {
	// set up TCP listener

	ctx, cancel := context.WithCancel(upstreamCtx)
	defer cancel()

	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", m.cfg.MutualAuthListenerPort))
	if err != nil {
		m.log.Error("Failed to start mutual auth listener", logfields.Error, err)
		os.Exit(1)
	}
	go func() { // shutdown socket goroutine
		<-ctx.Done()
		l.Close()
	}()

	m.log.Info("Started mutual auth listener", logfields.Port, m.cfg.MutualAuthListenerPort)
	ready <- struct{}{} // signal to hive that we are ready to accept connections

	for {
		conn, err := l.Accept()
		if err != nil {
			m.log.Error("Failed to accept connection", logfields.Error, err)
			if errors.Is(err, net.ErrClosed) {
				m.log.Info("Mutual auth listener socket got closed")
				return
			}
			continue
		}
		go m.handleConnection(ctx, conn)
	}
}

func (m *mutualAuthHandler) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	caBundle, err := m.cert.GetTrustBundle()
	if err != nil {
		m.log.Error("failed to get CA bundle", logfields.Error, err)
		return
	}

	tlsConn := tls.Server(conn, &tls.Config{
		ClientAuth:     tls.RequireAndVerifyClientCert,
		GetCertificate: m.GetCertificateForIncomingConnection,
		MinVersion:     tls.VersionTLS13,
		ClientCAs:      caBundle,
	})
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		m.log.Error("failed to perform TLS handshake", logfields.Error, err)
	}
}

func (m *mutualAuthHandler) GetCertificateForIncomingConnection(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.log.Debug("Got new TLS connection", logfields.SNI, info.ServerName)
	id, err := m.cert.SNIToNumericIdentity(info.ServerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity for SNI %s: %w", info.ServerName, err)
	}

	// this checks if the requested Security ID is present on the local node
	if m.endpointManager == nil {
		return nil, errors.New("endpoint manager is not loaded")
	}
	localEPs := m.endpointManager.GetEndpoints()
	matched := false
	for _, ep := range localEPs {
		if ep.SecurityIdentity != nil && ep.SecurityIdentity.ID == id {
			matched = true
			break
		}
	}

	if !matched {
		return nil, fmt.Errorf("no local endpoint present for identity %s", id.String())
	}

	return m.cert.GetCertificateForIdentity(id)
}

func (m *mutualAuthHandler) onStart(ctx cell.HookContext) error {
	m.log.Info("Starting mutual auth handler")

	listenCtx, cancel := context.WithCancel(context.Background())
	m.cancelSocketListen = cancel

	ready := make(chan struct{})
	go m.listenForConnections(listenCtx, ready)
	<-ready // wait for the socket to be ready
	return nil
}

func (m *mutualAuthHandler) onStop(ctx cell.HookContext) error {
	m.log.Info("Stopping mutual auth handler")
	m.cancelSocketListen()
	return nil
}

// verifyPeerCertificate is used for Go's TLS library to verify certificates
func (m *mutualAuthHandler) verifyPeerCertificate(id *identity.NumericIdentity, caBundle *x509.CertPool, certChains [][]*x509.Certificate) (*time.Time, error) {
	if len(certChains) == 0 {
		return nil, fmt.Errorf("no certificate chains found")
	}

	var expirationTime *time.Time

	for _, chain := range certChains {
		opts := x509.VerifyOptions{
			Roots:         caBundle,
			Intermediates: x509.NewCertPool(),
		}

		var leaf *x509.Certificate
		for _, cert := range chain {
			if cert.IsCA {
				opts.Intermediates.AddCert(cert)
			} else {
				leaf = cert
			}
		}
		if leaf == nil {
			return nil, fmt.Errorf("no leaf certificate found")
		}
		if _, err := leaf.Verify(opts); err != nil {
			return nil, fmt.Errorf("failed to verify certificate: %w", err)
		}

		if id != nil { // this will be empty in the peer connection
			m.log.Debug("Validating Server SNI", logfields.SNIID, id)
			if valid, err := m.cert.ValidateIdentity(*id, leaf); err != nil {
				return nil, fmt.Errorf("failed to validate SAN: %w", err)
			} else if !valid {
				return nil, fmt.Errorf("unable to validate SAN")
			}
		}

		expirationTime = &leaf.NotAfter

		m.log.Debug("Validated certificate", logfields.URISan, leaf.URIs)
	}

	return expirationTime, nil
}

func (m *mutualAuthHandler) subscribeToRotatedIdentities() <-chan certs.CertificateRotationEvent {
	return m.cert.SubscribeToRotatedIdentities()
}

func (m *mutualAuthHandler) certProviderStatus() *models.Status {
	return m.cert.Status()
}
