// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/crypto/certloader"
)

func newCA(t *testing.T, caCertPath string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	certRaw, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	certFile, err := os.Create(caCertPath)
	require.NoError(t, err)
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certRaw})
	require.NoError(t, err)
	certFile.Close()

	return ca, caKey
}

func writeNewCertAndKey(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, certPath, keyPath string) {
	t.Helper()

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "*.test.cilium.io",
		},
		DNSNames:    []string{"*.test.cilium.io", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	certRaw, err := x509.CreateCertificate(rand.Reader, cert, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)

	certFile, err := os.Create(certPath)
	require.NoError(t, err)
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certRaw})
	require.NoError(t, err)
	certFile.Close()

	keyFile, err := os.Create(keyPath)
	require.NoError(t, err)
	err = pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	require.NoError(t, err)
	keyFile.Close()
}

// startMTLSServer starts a /metrics handler over TLS with mTLS enforced using
// the given certificate files, and returns the server's listening address.
func startMTLSServer(t *testing.T, caCertPath, serverCertPath, serverKeyPath string) string {
	t.Helper()

	watchedConfig, err := certloader.NewWatchedServerConfig(
		slog.Default(), []string{caCertPath}, serverCertPath, serverKeyPath,
	)
	require.NoError(t, err)

	tlsConfig := watchedConfig.ServerConfig(&tls.Config{MinVersion: tls.VersionTLS13})
	listener, err := tls.Listen("tcp", "localhost:0", tlsConfig)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	go http.Serve(listener, mux) //nolint:errcheck

	return listener.Addr().String()
}

// TestAgentPrometheusMetricsMTLS verifies that the /metrics endpoint enforces
// mTLS: clients without a certificate are rejected, and clients presenting a
// certificate signed by the configured CA are accepted.
func TestAgentPrometheusMetricsMTLS(t *testing.T) {
	certDir := t.TempDir()
	caCertPath := filepath.Join(certDir, "ca.crt")
	serverCertPath := filepath.Join(certDir, "server.crt")
	serverKeyPath := filepath.Join(certDir, "server.key")
	clientCertPath := filepath.Join(certDir, "client.crt")
	clientKeyPath := filepath.Join(certDir, "client.key")

	caCert, caKey := newCA(t, caCertPath)
	writeNewCertAndKey(t, caCert, caKey, serverCertPath, serverKeyPath)
	writeNewCertAndKey(t, caCert, caKey, clientCertPath, clientKeyPath)

	caCertPEM, err := os.ReadFile(caCertPath)
	require.NoError(t, err)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertPEM)

	addr := startMTLSServer(t, caCertPath, serverCertPath, serverKeyPath)
	metricsURL := "https://" + addr + "/metrics"

	t.Run("rejects client without certificate", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    caCertPool,
					MinVersion: tls.VersionTLS13,
				},
			},
		}
		_, err := client.Get(metricsURL)
		require.Error(t, err, "mTLS server must reject clients that present no certificate")
	})

	t.Run("accepts client with valid certificate", func(t *testing.T) {
		clientCertPair, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		require.NoError(t, err)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      caCertPool,
					Certificates: []tls.Certificate{clientCertPair},
					MinVersion:   tls.VersionTLS13,
				},
			},
		}
		resp, err := client.Get(metricsURL)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
