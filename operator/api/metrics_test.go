// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/go-openapi/runtime"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/operator/models"
	"github.com/cilium/cilium/api/v1/operator/server/restapi/metrics"
	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	"github.com/cilium/cilium/pkg/hive"
	cellMetric "github.com/cilium/cilium/pkg/metrics"
	ciliumMetrics "github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/safeio"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	certDir        = "tls/"
	caCertPath     = certDir + "ca.crt"
	serverCertPath = certDir + "server.crt"
	serverKeyPath  = certDir + "server.key"
)

func TestMetricsHandlerWithoutMetrics(t *testing.T) {
	defer testutils.GoleakVerifyNone(
		t,
		// ignore goroutine started from sigs.k8s.io/controller-runtime/pkg/log.go init function
		testutils.GoleakIgnoreTopFunction("time.Sleep"),
	)

	rr := httptest.NewRecorder()

	hive := hive.New(
		cell.Provide(ciliumMetrics.NewRegistry),
		cell.Provide(func() (*option.DaemonConfig, ciliumMetrics.RegistryConfig) {
			return option.Config, ciliumMetrics.RegistryConfig{}
		}),
		cell.Provide(func() operatorMetrics.SharedConfig {
			return operatorMetrics.SharedConfig{
				EnableMetrics: false,
			}
		}),

		MetricsHandlerCell,

		// transform GetMetricsHandler in a http.HandlerFunc to use
		// the http package testing facilities
		cell.Provide(func(h metrics.GetMetricsHandler) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				res := h.Handle(metrics.GetMetricsParams{})
				res.WriteResponse(w, runtime.TextProducer())
			}
		}),

		cell.Invoke(func(hf http.HandlerFunc) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/metrics", nil)
			hf.ServeHTTP(rr, req)
		}),
	)

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected http status code %d, got %d", http.StatusOK, rr.Result().StatusCode)
	}

	body, err := safeio.ReadAllLimit(rr.Result().Body, safeio.MB)
	if err != nil {
		t.Fatalf("error while reading response body: %s", err)
	}
	rr.Result().Body.Close()

	var metrics []models.Metric
	if err := json.Unmarshal(body, &metrics); err != nil {
		t.Fatalf("error while unmarshaling response body: %s", err)
	}

	if len(metrics) != 0 {
		t.Fatalf("no metrics expected, found %v", metrics)
	}

	if err := hive.Stop(tlog, t.Context()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestMetricsHandlerWithMetrics(t *testing.T) {
	defer testutils.GoleakVerifyNone(
		t,
		// ignore goroutine started from sigs.k8s.io/controller-runtime/pkg/log.go init function
		testutils.GoleakIgnoreTopFunction("time.Sleep"),
	)

	rr := httptest.NewRecorder()

	hive := hive.New(
		operatorMetrics.Cell,
		cell.Provide(func() operatorMetrics.SharedConfig {
			return operatorMetrics.SharedConfig{
				EnableMetrics: true,
			}
		}),
		cell.Provide(func() *option.DaemonConfig {
			return option.Config
		}),

		cellMetric.Metric(newTestMetrics),

		MetricsHandlerCell,

		// transform GetMetricsHandler in a http.HandlerFunc to use
		// the http package testing facilities
		cell.Provide(func(h metrics.GetMetricsHandler) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				res := h.Handle(metrics.GetMetricsParams{})
				res.WriteResponse(w, runtime.TextProducer())
			}
		}),

		cell.Invoke(func(lc cell.Lifecycle, metrics *testMetrics, hf http.HandlerFunc) {
			lc.Append(cell.Hook{
				OnStart: func(cell.HookContext) error {
					// set values for some metrics
					metrics.MetricA.
						WithLabelValues("success").
						Inc()

					req := httptest.NewRequest(http.MethodGet, "http://localhost/metrics", nil)
					hf.ServeHTTP(rr, req)

					return nil
				},
			})
		}),
	)

	// Enabling the metrics for the operator will also start the prometheus server.
	// To avoid port clashing while testing, let the kernel pick an available port.
	hive.Viper().Set(operatorMetrics.OperatorPrometheusServeAddr, "localhost:0")

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected http status code %d, got %d", http.StatusOK, rr.Result().StatusCode)
	}

	body, err := safeio.ReadAllLimit(rr.Result().Body, safeio.MB)
	if err != nil {
		t.Fatalf("error while reading response body: %s", err)
	}
	rr.Result().Body.Close()

	var metrics []models.Metric
	if err := json.Unmarshal(body, &metrics); err != nil {
		t.Fatalf("error while unmarshaling response body: %s", err)
	}

	if err := testMetric(
		metrics,
		"operator_api_metrics_test_metric_a",
		float64(1),
		map[string]string{
			"outcome": "success",
		},
	); err != nil {
		t.Fatalf("error while inspecting metric: %s", err)
	}

	if err := hive.Stop(tlog, t.Context()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestMetricsHandlermTLS(t *testing.T) {
	defer testutils.GoleakVerifyNone(
		t,
		// ignore goroutine started from sigs.k8s.io/controller-runtime/pkg/log.go init function
		testutils.GoleakIgnoreTopFunction("time.Sleep"),
	)

	rr := httptest.NewRecorder()

	err := os.Mkdir(certDir, 0755)
	require.NoError(t, err)
	caCert, caKey := newCA(t)
	writeNewCertAndKey(t, caCert, caKey, serverCertPath, serverKeyPath)

	hive := hive.New(
		operatorMetrics.Cell,
		cell.Provide(func() operatorMetrics.SharedConfig {
			return operatorMetrics.SharedConfig{
				EnableMetrics: true,
			}
		}),
		cell.Provide(func() *option.DaemonConfig {
			return option.Config
		}),

		cellMetric.Metric(newTestMetrics),

		MetricsHandlerCell,

		// transform GetMetricsHandler in a http.HandlerFunc to use
		// the http package testing facilities
		cell.Provide(func(h metrics.GetMetricsHandler) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				res := h.Handle(metrics.GetMetricsParams{})
				res.WriteResponse(w, runtime.TextProducer())
			}
		}),

		cell.Invoke(func(lc cell.Lifecycle, metrics *testMetrics, hf http.HandlerFunc) {
			lc.Append(cell.Hook{
				OnStart: func(cell.HookContext) error {
					// set values for some metrics
					metrics.MetricA.
						WithLabelValues("success").
						Inc()

					req := httptest.NewRequest(http.MethodGet, "http://localhost/metrics", nil)
					hf.ServeHTTP(rr, req)

					return nil
				},
			})
		}),
	)

	// Enabling the metrics for the operator will also start the prometheus server.
	// To avoid port clashing while testing, let the kernel pick an available port.
	hive.Viper().Set(operatorMetrics.OperatorPrometheusServeAddr, "localhost:0")
	hive.Viper().Set(operatorMetrics.OperatorPrometheusEnableTLS, true)
	hive.Viper().Set(operatorMetrics.OperatorPrometheusTLSCertFile, serverCertPath)
	hive.Viper().Set(operatorMetrics.OperatorPrometheusTLSKeyFile, serverKeyPath)
	hive.Viper().Set(operatorMetrics.OperatorPrometheusTLSClientCAFiles, caCertPath)

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected http status code %d, got %d", http.StatusOK, rr.Result().StatusCode)
	}

	body, err := safeio.ReadAllLimit(rr.Result().Body, safeio.MB)
	if err != nil {
		t.Fatalf("error while reading response body: %s", err)
	}
	rr.Result().Body.Close()

	var metrics []models.Metric
	if err := json.Unmarshal(body, &metrics); err != nil {
		t.Fatalf("error while unmarshaling response body: %s", err)
	}

	if err := testMetric(
		metrics,
		"operator_api_metrics_test_metric_a",
		float64(1),
		map[string]string{
			"outcome": "success",
		},
	); err != nil {
		t.Fatalf("error while inspecting metric: %s", err)
	}

	if err := hive.Stop(tlog, t.Context()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}

	err = os.RemoveAll(certDir)
	require.NoError(t, err)
}

func testMetric(metrics []models.Metric, name string, value float64, labels map[string]string,
) error {
	for _, metric := range metrics {
		if metric.Name == name {
			if metric.Value != value {
				return fmt.Errorf("expected value %f for %q, got %f", value, name, metric.Value)
			}
			if !reflect.DeepEqual(metric.Labels, labels) {
				return fmt.Errorf("expected labels map %v for %q, got %v", labels, name, metric.Labels)
			}
			return nil
		}
	}
	return fmt.Errorf("%q not found", name)
}

type testMetrics struct {
	MetricA metric.Vec[metric.Counter]
}

func newTestMetrics() *testMetrics {
	return &testMetrics{
		MetricA: metric.NewCounterVec(metric.CounterOpts{
			Namespace: "operator_api_metrics_test",
			Name:      "metric_a",
		}, []string{"outcome"}),
	}
}

func newCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
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

// writeNewCertAndKey create new cert and key file
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
