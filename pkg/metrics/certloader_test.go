// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func newCA(t *testing.T, caCertPath string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	certRaw, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	certFile, err := os.Create(caCertPath)
	require.NoError(t, err)
	err = pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certRaw,
	})
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
		DNSNames:    []string{"*.test.cilium.io"},
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
	err = pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certRaw,
	})
	require.NoError(t, err)
	certFile.Close()

	keyFile, err := os.Create(keyPath)
	require.NoError(t, err)
	err = pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	require.NoError(t, err)
	keyFile.Close()
}

func TestAgentPrometheusMetricsTLS(t *testing.T) {
	defer testutils.GoleakVerifyNone(
		t,
		testutils.GoleakIgnoreTopFunction("time.Sleep"),
	)

	certDir := t.TempDir()
	caCertPath := filepath.Join(certDir, "ca.crt")
	serverCertPath := filepath.Join(certDir, "server.crt")
	serverKeyPath := filepath.Join(certDir, "server.key")

	caCert, caKey := newCA(t, caCertPath)
	writeNewCertAndKey(t, caCert, caKey, serverCertPath, serverKeyPath)

	h := hive.New(
		metrics.Cell,
		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{}
		}),
	)

	// Use port 0 to let the kernel pick an available port and avoid conflicts.
	h.Viper().Set("prometheus-serve-addr", "localhost:0")
	h.Viper().Set(metrics.PrometheusEnableTLS, true)
	h.Viper().Set(metrics.PrometheusTLSCertFile, serverCertPath)
	h.Viper().Set(metrics.PrometheusTLSKeyFile, serverKeyPath)
	h.Viper().Set(metrics.PrometheusTLSClientCAFiles, caCertPath)

	tlog := hivetest.Logger(t)
	require.NoError(t, h.Start(tlog, t.Context()))
	require.NoError(t, h.Stop(tlog, t.Context()))
}
