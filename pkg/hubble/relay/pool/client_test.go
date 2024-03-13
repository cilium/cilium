// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pool

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	hubbleopts "github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

func TestGRPCClientConnBuilder_CertificateChange(t *testing.T) {
	cert, ca := newTestCAandCert(t)

	fTLSb := &fakeTLSConfigBuilder{
		cert: &cert,
		ca:   ca,
	}
	cb := GRPCClientConnBuilder{
		DialTimeout: 5 * time.Second,
		Options: []grpc.DialOption{
			grpc.WithBlock(),
			grpc.FailOnNonTempDialError(true),
			grpc.WithReturnConnectionError(),
		},
		TLSConfig: fTLSb,
	}
	dir, err := os.MkdirTemp("", t.Name())
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	list, err := net.Listen("unix", filepath.Join(dir, "relay.sock"))
	require.NoError(t, err)
	addr := list.Addr().String()

	s := newTestServer(cert, ca)
	go s.Serve(list)

	clientConn, err := cb.ClientConn(fmt.Sprintf("unix://%s", list.Addr().String()), "foo.test.cilium.io")
	require.NoError(t, err)
	hc := healthpb.NewHealthClient(clientConn)
	_, err = hc.Check(context.TODO(), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)

	cert, ca = newTestCAandCert(t)

	s.Stop()
	// Start server with new cert on same socket
	list, err = net.Listen("unix", addr)
	require.NoError(t, err)
	s = newTestServer(cert, ca)
	go s.Serve(list)
	defer s.Stop()

	// Update client certificate
	fTLSb.set(&cert, ca)

	require.Eventually(t, func() bool {
		_, err = hc.Check(context.TODO(), &healthpb.HealthCheckRequest{})
		if err != nil {
			t.Logf("Error %q conn state %q", err.Error(), clientConn.GetState().String())
		}
		return err == nil
	}, 20*time.Second, 100*time.Millisecond)

}

var _ certloader.ClientConfigBuilder = &fakeTLSConfigBuilder{}

type fakeTLSConfigBuilder struct {
	mu   lock.Mutex
	cert *tls.Certificate
	ca   *x509.CertPool
}

// ClientConfig implements certloader.ClientConfigBuilder.
func (f *fakeTLSConfigBuilder) ClientConfig(base *tls.Config) *tls.Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := base.Clone()
	c.RootCAs = f.ca
	c.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return f.cert, nil
	}
	return c
}

func (f *fakeTLSConfigBuilder) set(cert *tls.Certificate, ca *x509.CertPool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ca = ca
	f.cert = cert
}

// IsMutualTLS implements certloader.ClientConfigBuilder.
func (*fakeTLSConfigBuilder) IsMutualTLS() bool {
	return true
}

// newTestCAandCert create a new CA and a sigend certificate
func newTestCAandCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	caRaw, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caRaw,
	})
	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caPEM.Bytes())

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "*.test.cilium.io",
		},
		DNSNames:    []string{"*.test.cilium.io"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	certKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	certRaw, err := x509.CreateCertificate(rand.Reader, cert, ca, &certKey.PublicKey, caKey)
	require.NoError(t, err)
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certRaw,
	})
	require.NoError(t, err)
	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certKey),
	})
	require.NoError(t, err)
	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	require.NoError(t, err)

	return serverCert, certpool
}

func newTestServer(cert tls.Certificate, ca *x509.CertPool) *grpc.Server {
	serverOpts := []grpc.ServerOption{grpc.Creds(credentials.NewTLS(&tls.Config{ //nolint:gosec
		Certificates: []tls.Certificate{cert},
		RootCAs:      ca,
		ServerName:   "foo.test.cilium.io",
		MinVersion:   hubbleopts.MinTLSVersion,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca,
	}))}
	s := grpc.NewServer(serverOpts...)
	svc := health.NewServer()
	svc.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(s, svc)
	return s
}
