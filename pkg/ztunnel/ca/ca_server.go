// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ca

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/safeio"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

const (
	// bootstrapKeyPath is the private key used to bootstrap ZTunnel to CA
	// TLS connection.
	bootstrapKeyPath = "/etc/ztunnel/bootstrap-private.key"
	// bootstrapCertPath is the certificate used to bootstrap ZTunnel to CA
	// TLS connection.
	bootstrapCertPath = "/etc/ztunnel/bootstrap-root.crt"
	// caKeyPath is the private key used to sign client certificates.
	caKeyPath = "/etc/ztunnel/ca-private.key"
	// caCertPath is the root certificate trust anchor for issued client
	// certificates.
	caCertPath = "/etc/ztunnel/ca-root.crt"
)

var _ pb.IstioCertificateServiceServer = (*Server)(nil)

// Server is the built-in certificate authority server for zTunnel.
// It handles certificate signing requests (CSRs) from zTunnel and issues
// certificates for workload identities.
//
// When SPIRE is enabled, this server should not be started as zTunnel obtains
// certificates directly from SPIRE.
type Server struct {
	l         net.Listener
	g         *grpc.Server
	log       *slog.Logger
	epManager endpointmanager.EndpointManager
	caCert    *x509.Certificate
	// cache the PEM encoded certificate, we return this as the trust anchor
	// on zTunnel certificate creation requests.
	caCertPEM string
	caKey     *rsa.PrivateKey
	pb.UnimplementedIstioCertificateServiceServer
}

// newServer creates a new CA server instance.
func newServer(log *slog.Logger, epManager endpointmanager.EndpointManager) *Server {
	return &Server{
		log:       log,
		epManager: epManager,
	}
}

// init performs the required actions to initialize the certificate authority
// server by loading the CA certificate and private key.
func (s *Server) init() error {
	// caCertPath will be a PEM encoded certificate, we need to decode this
	// to DER to parse as an x509.Certificate and also cache the PEM string.
	certFile, err := os.OpenFile(caCertPath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open CA certificate file %s: %w", caCertPath, err)
	}
	defer func() {
		err := certFile.Close()
		if err != nil {
			s.log.Error("failed to close CA certificate file",
				logfields.Path,
				caCertPath,
				logfields.Error,
				err)
		}
	}()

	buf, err := safeio.ReadAllLimit(certFile, safeio.MB)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate file %s: %w", caCertPath, err)
	}

	s.caCertPEM = string(buf)

	block, _ := pem.Decode(buf)
	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("CA certificate file %s is not a valid PEM encoded certificate", caCertPath)
	}

	s.caCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate file %s: %w", caCertPath, err)
	}

	// caKeyPath will be a PEM encoded certificate. We can parse this into an
	// rsa.PrivateKey.
	keyFile, err := os.OpenFile(caKeyPath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open CA private key file %s: %w",
			caKeyPath,
			err)
	}
	defer func() {
		err := keyFile.Close()
		if err != nil {
			s.log.Error("failed to close CA private key file",
				logfields.Path,
				caKeyPath,
				logfields.Error,
				err)
		}
	}()

	buf, err = safeio.ReadAllLimit(keyFile, safeio.MB)
	if err != nil {
		return fmt.Errorf("failed to read CA private key file %s: %w", caKeyPath, err)
	}

	block, _ = pem.Decode(buf)
	if block.Type != "PRIVATE KEY" {
		return fmt.Errorf("CA private key file %s is not a valid PEM encoded RSA private key", caKeyPath)
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA private key file %s: %w", caKeyPath, err)
		}

		// only support RSA keys for now.
		var ok bool
		if s.caKey, ok = key.(*rsa.PrivateKey); !ok {
			return fmt.Errorf("CA private key file %s is not a valid RSA private key", caKeyPath)
		}
	case "RSA PRIVATE KEY":
		// this block type parses directly to an RSA private key.
		s.caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA private key file %s: %w", caKeyPath, err)
		}

	default:
		return fmt.Errorf("CA private key file %s is not a valid PEM encoded RSA private key, got %q", caKeyPath, block.Type)
	}

	return nil
}

// Serve initializes the CA server and starts the gRPC server.
func (s *Server) Serve() error {
	var err error

	if err = s.init(); err != nil {
		return fmt.Errorf("failed to initialize CA: %w", err)
	}

	creds, err := credentials.NewServerTLSFromFile(bootstrapCertPath, bootstrapKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create gRPC TLS credentials: %w", err)
	}

	// keepalive options match config values from istio
	grpcOptions := []grpc.ServerOption{
		grpc.Creds(creds),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime: 15 * time.Second,
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:                  30 * time.Second,
			Timeout:               10 * time.Second,
			MaxConnectionAge:      time.Duration(math.MaxInt64),
			MaxConnectionAgeGrace: 10 * time.Second,
		}),
	}

	s.g = grpc.NewServer(grpcOptions...)
	pb.RegisterIstioCertificateServiceServer(s.g, s)

	s.l, err = net.Listen("tcp", "127.0.0.1:15012")
	if err != nil {
		return fmt.Errorf("failed to listen on CA address: %w", err)
	}

	s.log.Info("zTunnel CA server started")
	go func() {
		if err = s.g.Serve(s.l); err != nil {
			s.log.Error("CA gRPC server error", logfields.Error, err)
		}
	}()
	return nil
}

// GracefulStop halts the server gracefully.
func (s *Server) GracefulStop() {
	if s.g != nil {
		s.g.GracefulStop()
	}
}

// createCertificate will generate a certificate given a CSR and return the
// PEM encoded string.
func (s *Server) createCertificate(req *x509.CertificateRequest) (string, error) {
	// generate the certificate serial
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        req.Subject,
		URIs:           req.URIs,
		DNSNames:       req.DNSNames,
		IPAddresses:    req.IPAddresses,
		EmailAddresses: req.EmailAddresses,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(30 * (24 * time.Hour)),
	}

	der, err := x509.CreateCertificate(rand.Reader, certTemplate, s.caCert, req.PublicKey, s.caKey)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(pemBytes), nil
}

// CreateCertificate implements the certificate signing process.
func (s *Server) CreateCertificate(ctx context.Context, csr *pb.IstioCertificateRequest) (*pb.IstioCertificateResponse, error) {
	s.log.Debug("received CSR request")

	if len(csr.Csr) == 0 {
		return nil, fmt.Errorf("received empty CSR")
	}

	buf := bytes.NewBufferString(csr.Csr)

	block, _ := pem.Decode(buf.Bytes())
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("not a certificate signing request")
	}

	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	if err = req.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature check failed: %w", err)
	}

	if len(req.URIs) != 1 {
		return nil, fmt.Errorf("CSR must contain exactly one URI SAN")
	}

	uri := req.URIs[0]

	if uri.Scheme != "spiffe" {
		return nil, fmt.Errorf("CSR URI scheme must be 'spiffe', got %q", uri.Scheme)
	}

	fields := strings.Split(uri.Path, "/")
	// 5 fields since uri has leading '/', strings.Split will never omit empty
	// fields.
	if len(fields) != 5 {
		return nil, fmt.Errorf("CSR URI path must be in the format /ns/<namespace>/sa/<service-account>, got %q %q", uri.Path, fields)
	}
	k8sNamespace := fields[2]
	k8sSA := fields[4]

	// we must confirm at least one endpoint with the k8s namespace and
	// service account in the CSR exists on the node.
	//
	// this is a security measure ensuring we do not issue certificates for
	// pods that are not available on the host.
	eps := s.epManager.GetEndpointsByServiceAccount(k8sNamespace, k8sSA)
	if len(eps) == 0 {
		return nil, fmt.Errorf("no endpoints found for service account %s in namespace %s", k8sSA, k8sNamespace)
	}

	pemCert, err := s.createCertificate(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	s.log.Debug("created certificate for service account",
		logfields.K8sNamespace, k8sNamespace,
		logfields.K8sServiceAccount, k8sSA,
	)
	resp := &pb.IstioCertificateResponse{
		CertChain: []string{
			pemCert,
			s.caCertPEM,
		},
	}
	return resp, nil
}
