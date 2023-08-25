// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/go-openapi/runtime"
	"go.uber.org/goleak"

	"github.com/cilium/cilium/api/v1/operator/models"
	"github.com/cilium/cilium/api/v1/operator/server/restapi/metrics"
	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/safeio"
)

func TestMetricsHandlerWithoutMetrics(t *testing.T) {
	defer goleak.VerifyNone(
		t,
		// ignore goroutine started from sigs.k8s.io/controller-runtime/pkg/log.go init function
		goleak.IgnoreTopFunction("time.Sleep"),
	)

	rr := httptest.NewRecorder()

	hive := hive.New(
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

	if err := hive.Start(context.Background()); err != nil {
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

	var metrics []models.Metric
	if err := json.Unmarshal(body, &metrics); err != nil {
		t.Fatalf("error while unmarshaling response body: %s", err)
	}

	if len(metrics) != 0 {
		t.Fatalf("no metrics expected, found %v", metrics)
	}

	if err := hive.Stop(context.Background()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestMetricsHandlerWithMetrics(t *testing.T) {
	defer goleak.VerifyNone(
		t,
		// ignore goroutine started from sigs.k8s.io/controller-runtime/pkg/log.go init function
		goleak.IgnoreTopFunction("time.Sleep"),
	)

	rr := httptest.NewRecorder()

	hive := hive.New(
		MetricsHandlerCell,

		// transform GetMetricsHandler in a http.HandlerFunc to use
		// the http package testing facilities
		cell.Provide(func(h metrics.GetMetricsHandler) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				res := h.Handle(metrics.GetMetricsParams{})
				res.WriteResponse(w, runtime.TextProducer())
			}
		}),

		cell.Invoke(func(lc hive.Lifecycle, hf http.HandlerFunc) {
			lc.Append(hive.Hook{
				OnStart: func(hive.HookContext) error {
					// registering the metrics for the operator will start the
					// prometheus server. To avoid port clashing while testing,
					// let the kernel pick an available port.
					operatorOption.Config.OperatorPrometheusServeAddr = "localhost:0"

					// registers metrics for the cilium-operator
					operatorMetrics.Register()

					// set values for some operator metrics
					operatorMetrics.IdentityGCSize.
						WithLabelValues(operatorMetrics.LabelValueOutcomeAlive).
						Set(float64(12))
					operatorMetrics.IdentityGCRuns.
						WithLabelValues(operatorMetrics.LabelValueOutcomeSuccess).
						Set(float64(15))
					operatorMetrics.EndpointGCObjects.
						WithLabelValues(operatorMetrics.LabelValueOutcomeSuccess).
						Inc()

					req := httptest.NewRequest(http.MethodGet, "http://localhost/metrics", nil)
					hf.ServeHTTP(rr, req)

					return nil
				},
				OnStop: func(ctx hive.HookContext) error {
					// unregister metrics for cilium-operator
					operatorMetrics.Unregister()

					return nil
				},
			})
		}),
	)

	if err := hive.Start(context.Background()); err != nil {
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
		"cilium_operator_identity_gc_entries",
		float64(12),
		map[string]string{
			operatorMetrics.LabelStatus: operatorMetrics.LabelValueOutcomeAlive,
		},
	); err != nil {
		t.Fatalf("error while inspecting metric: %s", err)
	}
	if err := testMetric(
		metrics,
		"cilium_operator_identity_gc_runs",
		float64(15),
		map[string]string{
			operatorMetrics.LabelOutcome: operatorMetrics.LabelValueOutcomeSuccess,
		},
	); err != nil {
		t.Fatalf("error while inspecting metric: %s", err)
	}
	if err := testMetric(
		metrics,
		"cilium_operator_endpoint_gc_objects",
		float64(1),
		map[string]string{
			operatorMetrics.LabelOutcome: operatorMetrics.LabelValueOutcomeSuccess,
		},
	); err != nil {
		t.Fatalf("error while inspecting metric: %s", err)
	}

	if err := hive.Stop(context.Background()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
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
