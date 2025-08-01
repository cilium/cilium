// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"istio.io/api/security/v1alpha1"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// bootstrapKeyPath is the private key used to boostrap ZTunnel to CA
	// TLS connection.
	bootstrapKeyPath = "/etc/ztunnel/bootstrap-private.key"
	// bootstrapCertPath is the certificate used to boostrap ZTunnel to CA
	// TLS connection.
	bootstrapCertPath = "/etc/ztunnel/bootstrap-root.crt"
	// caKeyPath is the private key used to sign client certificates.
	caKeyPath = "/etc/ztunnel/ca-private.key"
	// caCertPath is the root certificate trust anchor for issued client
	// certificates.
	caCertPath = "/etc/ztunnel/ca-root.crt"
)

var _ v1alpha1.IstioCertificateServiceServer = (*Server)(nil)

// Server is a private implemenation of xDS for use with the stand-alone
// zTunnel proxy.
//
// This xDS server will implement a scoped-down xDS API consisting of a
// certificate authority capable of signing CSR(s)s submitted by zTunnel and a
// control plane capable of sending workload and service events to zTunnel.
type Server struct {
	l        net.Listener
	g        *grpc.Server
	log      *slog.Logger
	epLookup endpointmanager.EndpointsLookup
	caCert   *x509.Certificate
	// cache the PEM encoded certificate, we return this as the trust anchor
	// on zTunnel certificate creation requests.
	caCertPEM string
	caKey     *rsa.PrivateKey
	v1alpha1.UnimplementedIstioCertificateServiceServer
}

func newServer(log *slog.Logger, epLookup endpointmanager.EndpointsLookup) (*Server, error) {
	x := &Server{
		log:      log,
		epLookup: epLookup,
	}
	return x, nil
}

// initCA performs the required action to initialize the certificate authority
// server.
func (x *Server) initCA() error {
	// caCertPath will be a PEM encoded certificate, we need to decode this
	// to DER to parse as an x509.Certificate and also cache the PEM string.
	certFile, err := os.OpenFile(caCertPath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open CA certificate file %s: %w", caCertPath, err)
	}
	defer func() {
		err := certFile.Close()
		if err != nil {
			x.log.Error("failed to close CA certificate file", logfields.Path, caCertPath, logfields.Error, err)
		}
	}()

	buf, err := io.ReadAll(certFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate file %s: %w", caCertPath, err)
	}

	x.caCertPEM = string(buf)

	block, _ := pem.Decode(buf)
	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("CA certificate file %s is not a valid PEM encoded certificate", caCertPath)
	}

	x.caCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate file %s: %w", caCertPath, err)
	}

	// caKeyPath will be a PEM encoded certificate. We can parse this into an
	// rsa.PrivateKey.
	keyFile, err := os.OpenFile(caKeyPath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open CA private key file %s: %w", caKeyPath, err)
	}
	defer func() {
		err := keyFile.Close()
		if err != nil {
			x.log.Error("failed to close CA private key file", logfields.Path, caKeyPath, logfields.Error, err)
		}
	}()

	buf, err = io.ReadAll(keyFile)
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
		if x.caKey, ok = key.(*rsa.PrivateKey); !ok {
			return fmt.Errorf("CA private key file %s is not a valid RSA private key", caKeyPath)
		}
	case "RSA PRIVATE KEY":
		// this block type parses directly to an RSA private key.
		x.caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA private key file %s: %w", caKeyPath, err)
		}

	default:
		return fmt.Errorf("CA private key file %s is not a valid PEM encoded RSA private key, got %q", caKeyPath, block.Type)
	}

	x.log.Debug("initialized CA")

	return nil
}

// Serve will create the listening gRPC service and register the required xDS
// endpoints.
//
// If Serve returns without an error the gRPC server is launched within a new
// go routine.
//
// Server.GracefulStop() can be used to kill the running gRPC server.
func (x *Server) Serve() error {
	var err error

	// Note: this initialization code could technically be done during
	// construction, but due to hive/cell needing construction to happen without
	// side effects, do it right before serving.
	if err = x.initCA(); err != nil {
		return fmt.Errorf("failed to initialize CA: %w", err)
	}

	creds, err := credentials.NewServerTLSFromFile(bootstrapCertPath, bootstrapKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create gRPC TLS credentials: %w", err)
	}

	x.g = grpc.NewServer(grpc.Creds(creds))

	v1alpha1.RegisterIstioCertificateServiceServer(x.g, x)

	x.l, err = net.Listen("tcp", "127.0.0.1:15012")
	if err != nil {
		return err
	}

	x.log.Info("zTunnel xDS server started")
	go func() {
		if err = x.g.Serve(x.l); err != nil {
			x.log.Error("gRPC server error", logfields.Error, err)
		}
	}()
	return nil
}

// GracefulStop halts the server gracefully, returning a nil error from the
// underlying gRPC server.
//
// This is useful to kill the server without producing a conflated error that
// would occur when net.Listen() returns an error.
func (x *Server) GracefulStop() {
	x.g.GracefulStop()
}

// createCertificate will generate a certificate given a CSR and return the
// PEM encoded string.
func (x *Server) createCertificate(req *x509.CertificateRequest) (string, error) {
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

	der, err := x509.CreateCertificate(rand.Reader, certTemplate, x.caCert, req.PublicKey, x.caKey)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate: %w", err)
	}

	pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(pem), nil
}

// CreateCertificate implements the certificate signing process.
func (x *Server) CreateCertificate(ctx context.Context, csr *v1alpha1.IstioCertificateRequest) (*v1alpha1.IstioCertificateResponse, error) {
	x.log.Debug("received CSR request")

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
	eps := x.epLookup.GetEndpointsByServiceAccount(k8sNamespace, k8sSA)
	if len(eps) == 0 {
		return nil, fmt.Errorf("no endpoints found for service account %s in namespace %s", k8sSA, k8sNamespace)
	}

	pem, err := x.createCertificate(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	x.log.Debug("created certificate for service account",
		logfields.K8sNamespace, k8sNamespace,
		logfields.K8sServiceAccount, k8sSA,
	)
	resp := &v1alpha1.IstioCertificateResponse{
		CertChain: []string{
			pem,
			x.caCertPEM,
		},
	}
	return resp, nil
}
