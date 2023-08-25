// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"go.uber.org/goleak"

	operatorApi "github.com/cilium/cilium/api/v1/operator/server"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

func TestAPIServerK8sDisabled(t *testing.T) {
	defer goleak.VerifyNone(
		t,
		// ignore goroutine started from sigs.k8s.io/controller-runtime/pkg/log.go init function
		goleak.IgnoreTopFunction("time.Sleep"),
	)

	var testSrv Server

	hive := hive.New(
		k8sClient.FakeClientCell,
		cell.Invoke(func(cs *k8sClient.FakeClientset) {
			cs.Disable()
		}),
		MetricsHandlerCell,
		HealthHandlerCell(
			func() bool {
				return false
			},
			func() bool {
				return true
			},
		),
		cell.Provide(func() Config {
			return Config{
				OperatorAPIServeAddr: "localhost:0",
			}
		}),

		operatorApi.SpecCell,
		cell.Provide(newServer),

		cell.Invoke(func(srv Server) {
			testSrv = srv
		}),
	)

	if err := hive.Start(context.Background()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	if len(testSrv.Ports()) != 1 {
		t.Fatalf("expected a single opened port, got: %v", len(testSrv.Ports()))
	}
	port := testSrv.Ports()[0]

	if err := testEndpoint(t, port, "/v1/metrics", http.StatusOK); err != nil {
		t.Fatalf("failed to query endpoint: %s", err)
	}
	if err := testEndpoint(t, port, "/v1/healthz", http.StatusNotImplemented); err != nil {
		t.Fatalf("failed to query endpoint: %s", err)
	}
	if err := testEndpoint(t, port, "/healthz", http.StatusNotImplemented); err != nil {
		t.Fatalf("failed to query endpoint: %s", err)
	}

	if err := hive.Stop(context.Background()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestAPIServerK8sEnabled(t *testing.T) {
	defer goleak.VerifyNone(
		t,
		// ignore goroutine started from sigs.k8s.io/controller-runtime/pkg/log.go init function
		goleak.IgnoreTopFunction("time.Sleep"),
	)

	var testSrv Server

	hive := hive.New(
		k8sClient.FakeClientCell,
		MetricsHandlerCell,
		HealthHandlerCell(
			func() bool {
				return false
			},
			func() bool {
				return true
			},
		),
		cell.Provide(func() Config {
			return Config{
				OperatorAPIServeAddr: "localhost:0",
			}
		}),

		operatorApi.SpecCell,
		cell.Provide(newServer),

		cell.Invoke(func(srv Server) {
			testSrv = srv
		}),
	)

	if err := hive.Start(context.Background()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	if len(testSrv.Ports()) != 1 {
		t.Fatalf("expected a single opened port, got: %v", len(testSrv.Ports()))
	}
	port := testSrv.Ports()[0]

	if err := testEndpoint(t, port, "/v1/metrics", http.StatusOK); err != nil {
		t.Fatalf("failed to query endpoint: %s", err)
	}
	if err := testEndpoint(t, port, "/v1/healthz", http.StatusOK); err != nil {
		t.Fatalf("failed to query endpoint: %s", err)
	}
	if err := testEndpoint(t, port, "/healthz", http.StatusOK); err != nil {
		t.Fatalf("failed to query endpoint: %s", err)
	}

	if err := hive.Stop(context.Background()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func testEndpoint(t *testing.T, port int, path string, statusCode int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("http://localhost:%d%s", port, path),
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to create http request: %s", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request for %s failed: %s", path, err)
	}
	defer res.Body.Close()

	if res.StatusCode != statusCode {
		return fmt.Errorf("expected http status code %d, got: %d", statusCode, res.StatusCode)
	}

	return nil
}
