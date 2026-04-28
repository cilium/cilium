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
	"math/big"
	"os"
	"strings"

	"google.golang.org/grpc/credentials"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/safeio"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

const (
	// bootstrapKeyPath is the private key used to bootstrap the ztunnel to
	// CA TLS connection.
	bootstrapKeyPath = "/etc/ztunnel/bootstrap-private.key"
	// bootstrapCertPath is the certificate used to bootstrap the ztunnel to
	// CA TLS connection.
	bootstrapCertPath = "/etc/ztunnel/bootstrap-root.crt"
	// caKeyPath is the private key used to sign client certificates.
	caKeyPath = "/etc/ztunnel/ca-private.key"
	// caCertPath is the root certificate trust anchor for issued client
	// certificates.
	caCertPath = "/etc/ztunnel/ca-root.crt"
)

var _ pb.IstioCertificateServiceServer = (*Server)(nil)

// Server is the built-in certificate authority for the stand-alone ztunnel
// proxy. It signs CSRs submitted by ztunnel and returns workload identity
// certificates.
//
// Server does not own a listener or a *grpc.Server; the caller (the xDS
// server) is responsible for registering a Server on its own gRPC server via
// pb.RegisterIstioCertificateServiceServer.
type Server struct {
	log       *slog.Logger
	epManager endpointmanager.EndpointManager
	caCert    *x509.Certificate
	// caCertPEM caches the PEM encoded certificate; it is returned as the
	// trust anchor on ztunnel certificate creation requests.
	caCertPEM string
	caKey     *rsa.PrivateKey
	pb.UnimplementedIstioCertificateServiceServer
}

// NewServer initializes the built-in CA server by loading the CA certificate
// and private key from disk.
func NewServer(log *slog.Logger, epManager endpointmanager.EndpointManager) (*Server, error) {
	s := &Server{
		log:       log,
		epManager: epManager,
	}
	if err := s.init(); err != nil {
		return nil, err
	}
	return s, nil
}

// LoadServerTLSCredentials loads the bootstrap TLS credentials used by the
// gRPC server that hosts the certificate signing service.
func LoadServerTLSCredentials() (credentials.TransportCredentials, error) {
	return credentials.NewServerTLSFromFile(bootstrapCertPath, bootstrapKeyPath)
}

// init loads the CA certificate and private key from disk.
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
