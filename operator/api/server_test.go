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

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

func TestAPIServerDisabled(t *testing.T) {
	defer goleak.VerifyNone(
		t,
		// ignore goroutine started from sigs.k8s.io/controller-runtime/pkg/log.go init function
		goleak.IgnoreTopFunction("time.Sleep"),
	)

	var testSrv Server

	hive := hive.New(
		k8sClient.FakeClientCell,
		MetricsHandlerCell,
		HealthHandlerCell(func() bool {
			return false
		}),
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				EnableK8s: false,
			}
		}),
		cell.Provide(func() Config {
			return Config{
				OperatorAPIServeAddr: "localhost:0",
			}
		}),

		cell.Provide(newServer),

		cell.Invoke(func(srv Server) {
			testSrv = srv
		}),
	)

	if err := hive.Start(context.Background()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	if testSrv != nil {
		t.Fatalf("listeners unexpectedly started on ports %v", testSrv.Ports())
	}

	if err := hive.Stop(context.Background()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestAPIServerEnabled(t *testing.T) {
	defer goleak.VerifyNone(
		t,
		// ignore goroutine started from sigs.k8s.io/controller-runtime/pkg/log.go init function
		goleak.IgnoreTopFunction("time.Sleep"),
	)

	var testSrv Server

	hive := hive.New(
		k8sClient.FakeClientCell,
		MetricsHandlerCell,
		HealthHandlerCell(func() bool {
			return false
		}),
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				EnableK8s: true,
			}
		}),
		cell.Provide(func() Config {
			return Config{
				OperatorAPIServeAddr: "localhost:0",
			}
		}),

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

	if err := testEndpoint(t, port, "/v1/healthz"); err != nil {
		t.Fatalf("failed to query endpoint: %s", err)
	}
	if err := testEndpoint(t, port, "/v1/metrics"); err != nil {
		t.Fatalf("failed to query endpoint: %s", err)
	}
	if err := testEndpoint(t, port, "/healthz"); err != nil {
		t.Fatalf("failed to query endpoint: %s", err)
	}

	if err := hive.Stop(context.Background()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func testEndpoint(t *testing.T, port int, path string) error {
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
		return fmt.Errorf("http request for healthz failed: %s", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("expected http status code %d, got: %d", http.StatusOK, res.StatusCode)
	}

	return nil
}
