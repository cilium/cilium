// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/go-openapi/runtime"

	"github.com/cilium/cilium/api/v1/operator/server/restapi/operator"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/safeio"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestHealthHandlerK8sDisabled(t *testing.T) {
	defer testutils.GoleakVerifyNone(
		t,
		// ignore goroutine started from sigs.k8s.io/controller-runtime/pkg/log.go init function
		testutils.GoleakIgnoreTopFunction("time.Sleep"),
	)

	rr := httptest.NewRecorder()

	hive := hive.New(
		k8sClient.FakeClientCell(),
		cell.Invoke(func(cs *k8sClient.FakeClientset) {
			cs.Disable()
		}),

		kvstore.Cell(kvstore.DisabledBackendName),

		HealthHandlerCell(
			func() bool {
				return false
			},
		),

		// transform GetHealthzHandler in a http.HandlerFunc to use
		// the http package testing facilities
		cell.Provide(func(h operator.GetHealthzHandler) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				res := h.Handle(operator.GetHealthzParams{})
				res.WriteResponse(w, runtime.TextProducer())
			}
		}),

		cell.Invoke(func(hf http.HandlerFunc) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/healthz", nil)
			hf.ServeHTTP(rr, req)
		}),
	)

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	if rr.Result().StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected http status code %d, got %d", http.StatusNotImplemented, rr.Result().StatusCode)
	}

	if err := hive.Stop(tlog, t.Context()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestHealthHandlerK8sEnabled(t *testing.T) {
	defer testutils.GoleakVerifyNone(
		t,
		// ignore goroutine started from sigs.k8s.io/controller-runtime/pkg/log.go init function
		testutils.GoleakIgnoreTopFunction("time.Sleep"),
	)

	rr := httptest.NewRecorder()

	hive := hive.New(
		k8sClient.FakeClientCell(),
		kvstore.Cell(kvstore.DisabledBackendName),

		HealthHandlerCell(
			func() bool {
				return false
			},
		),

		// transform GetHealthzHandler in a http.HandlerFunc to use
		// the http package testing facilities
		cell.Provide(func(h operator.GetHealthzHandler) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				res := h.Handle(operator.GetHealthzParams{})
				res.WriteResponse(w, runtime.TextProducer())
			}
		}),

		cell.Invoke(func(hf http.HandlerFunc) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/healthz", nil)
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

	body, err := safeio.ReadAllLimit(rr.Result().Body, safeio.KB)
	if err != nil {
		t.Fatalf("error while reading response body: %s", err)
	}
	rr.Result().Body.Close()

	if string(body) != "ok" {
		t.Fatalf("expected response body %q, got: %q", "ok", string(body))
	}

	if err := hive.Stop(tlog, t.Context()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}
