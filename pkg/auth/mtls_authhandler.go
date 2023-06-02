// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/auth/certs"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
)

type mtlsParams struct {
	cell.In

	CertificateProvider certs.CertificateProvider
}

func newMTLSAuthHandler(lc hive.Lifecycle, cfg MTLSConfig, params mtlsParams, log logrus.FieldLogger) authHandlerResult {
	if cfg.MTLSListenerPort == 0 {
		log.Info("mTLS Auth Handler is disabled as no port is configured")
		return authHandlerResult{}
	}
	if params.CertificateProvider == nil {
		log.Fatal("No certificate provider configured, but one is required. Please check if the spire flags are configured.")
	}

	mtls := &mtlsAuthHandler{
		cfg:  cfg,
		log:  log.WithField(logfields.LogSubsys, "mtls-auth-handler"),
		cert: params.CertificateProvider,
	}

	lc.Append(hive.Hook{OnStart: mtls.onStart, OnStop: mtls.onStop})

	return authHandlerResult{
		AuthHandler: mtls,
	}
}

type MTLSConfig struct {
	MTLSListenerPort int `mapstructure:"mesh-auth-mtls-listener-port"`
}

func (cfg MTLSConfig) Flags(flags *pflag.FlagSet) {
	flags.IntVar(&cfg.MTLSListenerPort, "mesh-auth-mtls-listener-port", 0, "Port on which the Cilium Agent will perfom mTLS handshakes between other Agents")
}

type mtlsAuthHandler struct {
	cell.In

	cfg MTLSConfig
	log logrus.FieldLogger

	cert certs.CertificateProvider

	cancelSocketListen context.CancelFunc
}

func (m *mtlsAuthHandler) authenticate(ar *authRequest) (*authResponse, error) {
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
	conn, err := net.Dial("tcp", net.JoinHostPort(ar.remoteNodeIP, strconv.Itoa(m.cfg.MTLSListenerPort)))
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s:%d: %w", ar.remoteNodeIP, m.cfg.MTLSListenerPort, err)
	}
	defer conn.Close()

	var expirationTime *time.Time = &clientCert.Leaf.NotAfter

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

func (m *mtlsAuthHandler) authType() policy.AuthType {
	return policy.AuthTypeMTLSSpiffe
}

func (m *mtlsAuthHandler) listenForConnections(upstreamCtx context.Context, ready chan<- struct{}) {
	// set up TCP listener

	ctx, cancel := context.WithCancel(upstreamCtx)
	defer cancel()

	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", m.cfg.MTLSListenerPort))
	if err != nil {
		m.log.WithError(err).Fatal("Failed to start mTLS listener")
	}
	go func() { // shutdown socket goroutine
		<-ctx.Done()
		l.Close()
	}()

	m.log.WithField(logfields.Port, m.cfg.MTLSListenerPort).Info("Started mTLS listener")
	ready <- struct{}{} // signal to hive that we are ready to accept connections

	for {
		conn, err := l.Accept()
		if err != nil {
			m.log.WithError(err).Error("Failed to accept connection")
			if errors.Is(err, net.ErrClosed) {
				m.log.Info("mTLS listener socket got closed")
				return
			}
			continue
		}
		go m.handleConnection(ctx, conn)
	}
}

func (m *mtlsAuthHandler) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	caBundle, err := m.cert.GetTrustBundle()
	if err != nil {
		m.log.WithError(err).Error("failed to get CA bundle")
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
		m.log.WithError(err).Error("failed to perform TLS handshake")
	}
}

func (m *mtlsAuthHandler) GetCertificateForIncomingConnection(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.log.WithField("SNI", info.ServerName).Debug("Got new TLS connection")
	id, err := m.cert.SNIToNumericIdentity(info.ServerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity for SNI %s: %w", info.ServerName, err)
	}

	return m.cert.GetCertificateForIdentity(id)
}

func (m *mtlsAuthHandler) onStart(ctx hive.HookContext) error {
	m.log.Info("Starting mTLS auth handler")

	listenCtx, cancel := context.WithCancel(context.Background())
	m.cancelSocketListen = cancel

	ready := make(chan struct{})
	go m.listenForConnections(listenCtx, ready)
	<-ready // wait for the socket to be ready
	return nil
}

func (m *mtlsAuthHandler) onStop(ctx hive.HookContext) error {
	m.log.Info("Stopping mTLS auth handler")
	m.cancelSocketListen()
	return nil
}

// verifyPeerCertificate is used for Go's TLS library to verify certificates
func (m *mtlsAuthHandler) verifyPeerCertificate(id *identity.NumericIdentity, caBundle *x509.CertPool, certChains [][]*x509.Certificate) (*time.Time, error) {
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
			m.log.WithField("SNI ID", id.String()).Debug("Validating Server SNI")
			if valid, err := m.cert.ValidateIdentity(*id, leaf); err != nil {
				return nil, fmt.Errorf("failed to validate SAN: %w", err)
			} else if !valid {
				return nil, fmt.Errorf("unable to validate SAN")
			}
		}

		expirationTime = &leaf.NotAfter

		m.log.WithField("uri-san", leaf.URIs).Debug("Validated certificate")
	}

	return expirationTime, nil
}

func (m *mtlsAuthHandler) subscribeToRotatedIdentities() <-chan certs.CertificateRotationEvent {
	return m.cert.SubscribeToRotatedIdentities()
}
