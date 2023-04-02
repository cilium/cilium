// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pprof

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

func TestPprofDisabled(t *testing.T) {
	defer goleak.VerifyNone(t)

	var testSrv Server

	hive := hive.New(
		cell.Provide(newServer),
		cell.Config(Config{
			Pprof:        false,
			PprofAddress: "localhost",
			PprofPort:    0,
		}),
		cell.Invoke(func(srv Server) {
			testSrv = srv
		}),
	)

	if err := hive.Start(context.Background()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	if testSrv != nil {
		t.Fatalf("listener unexpectedly started on port %d", testSrv.Port())
	}

	if err := hive.Stop(context.Background()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestPprofHandlers(t *testing.T) {
	defer goleak.VerifyNone(t)

	var testSrv Server

	hive := hive.New(
		cell.Provide(newServer),
		cell.Config(Config{
			Pprof:        true,
			PprofAddress: "localhost",
			PprofPort:    0,
		}),
		cell.Invoke(func(srv Server) {
			testSrv = srv
		}),
	)

	if err := hive.Start(context.Background()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("http://localhost:%d/debug/pprof/heap", testSrv.Port()),
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create http request: %s", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http request for profiling data failed: %s", err)
	}

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected http status code %d, got: %d", http.StatusOK, res.StatusCode)
	}

	if err := hive.Stop(context.Background()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}
