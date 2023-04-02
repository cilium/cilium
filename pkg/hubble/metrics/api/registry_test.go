// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"context"
	"io"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/cilium/cilium/api/v1/flow"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

type testPlugin struct {
	handler Handler
}

func (t *testPlugin) NewHandler() Handler {
	return t.handler
}

func (t *testPlugin) HelpText() string {
	return ""
}

type testHandler struct {
	ContextOptions   *ContextOptions
	counter          *prometheus.CounterVec
	ProcessCalled    int
	InitCalled       int
	ListMetricCalled int
}

func (t *testHandler) Init(registry *prometheus.Registry, options Options) error {
	t.InitCalled++
	return nil
}

func (t *testHandler) Status() string {
	return ""
}

func (t *testHandler) Context() *ContextOptions {
	return t.ContextOptions
}

func (t *testHandler) ListMetricVec() []*prometheus.MetricVec {
	t.ListMetricCalled++
	return []*prometheus.MetricVec{t.counter.MetricVec}
}

func (t *testHandler) ProcessFlow(ctx context.Context, p *pb.Flow) error {
	labels, _ := t.ContextOptions.GetLabelValues(p)
	t.counter.WithLabelValues(labels...).Inc()
	t.ProcessCalled++
	return nil
}

func TestRegister(t *testing.T) {

	flow1 := &pb.Flow{
		EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypeAccessLog},
		L7: &pb.Layer7{
			Record: &pb.Layer7_Http{Http: &pb.HTTP{}},
		},
		Source:      &pb.Endpoint{Namespace: "foo", PodName: "foo-123"},
		Destination: &pb.Endpoint{Namespace: "bar", PodName: "bar-123"},
		Verdict:     pb.Verdict_FORWARDED,
	}

	flow2 := &pb.Flow{
		EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypeAccessLog},
		L7: &pb.Layer7{
			Record: &pb.Layer7_Http{Http: &pb.HTTP{}},
		},
		Source:      &pb.Endpoint{Namespace: "abc", PodName: "abc-456"},
		Destination: &pb.Endpoint{Namespace: "bar", PodName: "bar-123"},
		Verdict:     pb.Verdict_FORWARDED,
	}
	log := logrus.New()
	log.SetOutput(io.Discard)

	t.Run("Should not register handler", func(t *testing.T) {

		r := NewRegistry(log)

		handler := &testHandler{}

		r.Register("test", &testPlugin{handler: handler})

		handlers, err := r.ConfigureHandlers(nil, Map{})
		assert.EqualValues(t, err, nil)
		assert.EqualValues(t, len(handlers.handlers), 0)
	})

	t.Run("Should register handler", func(t *testing.T) {

		promRegistry := prometheus.NewRegistry()
		opts, _ := ParseContextOptions(Options{"sourceContext": "pod", "destinationContext": "pod"})
		initHandlers(t, opts, promRegistry, log)
	})

	t.Run("Should remove metrics series with ContextPod", func(t *testing.T) {

		promRegistry := prometheus.NewRegistry()
		opts, _ := ParseContextOptions(Options{"sourceContext": "pod", "destinationContext": "pod"})
		handlers := initHandlers(t, opts, promRegistry, log)

		handlers.ProcessFlow(context.TODO(), flow1)
		handlers.ProcessFlow(context.TODO(), flow2)
		assert.EqualValues(t, handlers.handlers[0].(*testHandler).ProcessCalled, 2)

		verifyMetricSeriesExists(t, promRegistry, 2)

		handlers.ProcessPodDeletion(&slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "foo-123",
				Namespace: "foo",
			},
		})
		assert.EqualValues(t, handlers.handlers[0].(*testHandler).ListMetricCalled, 1)

		verifyMetricSeriesExists(t, promRegistry, 1)

		handlers.ProcessPodDeletion(&slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "bar-123",
				Namespace: "bar",
			},
		})
		assert.EqualValues(t, handlers.handlers[0].(*testHandler).ListMetricCalled, 2)

		verifyMetricSeriesNotExists(t, promRegistry)
	})

	t.Run("Should not remove metrics series with ContextPodShort", func(t *testing.T) {

		promRegistry := prometheus.NewRegistry()
		opts, _ := ParseContextOptions(Options{"sourceContext": "pod-short", "destinationContext": "pod-short"})
		handlers := initHandlers(t, opts, promRegistry, log)

		handlers.ProcessFlow(context.TODO(), flow1)
		handlers.ProcessFlow(context.TODO(), flow2)
		assert.EqualValues(t, handlers.handlers[0].(*testHandler).ProcessCalled, 2)

		verifyMetricSeriesExists(t, promRegistry, 2)

		handlers.ProcessPodDeletion(&slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "foo-123",
				Namespace: "foo",
			},
		})
		assert.EqualValues(t, handlers.handlers[0].(*testHandler).ListMetricCalled, 1)

		verifyMetricSeriesExists(t, promRegistry, 2)

		handlers.ProcessPodDeletion(&slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "bar-123",
				Namespace: "bar",
			},
		})
		assert.EqualValues(t, handlers.handlers[0].(*testHandler).ListMetricCalled, 2)

		verifyMetricSeriesExists(t, promRegistry, 2)
	})

	t.Run("Should remove metrics series with LabelsContext", func(t *testing.T) {

		promRegistry := prometheus.NewRegistry()
		opts, _ := ParseContextOptions(Options{"labelsContext": "source_pod,source_namespace,destination_pod,destination_namespace"})
		handlers := initHandlers(t, opts, promRegistry, log)

		handlers.ProcessFlow(context.TODO(), flow1)
		handlers.ProcessFlow(context.TODO(), flow2)
		assert.EqualValues(t, handlers.handlers[0].(*testHandler).ProcessCalled, 2)

		verifyMetricSeriesExists(t, promRegistry, 2)

		handlers.ProcessPodDeletion(&slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "foo-123",
				Namespace: "foo",
			},
		})
		assert.EqualValues(t, handlers.handlers[0].(*testHandler).ListMetricCalled, 1)

		verifyMetricSeriesExists(t, promRegistry, 1)

		handlers.ProcessPodDeletion(&slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "bar-123",
				Namespace: "bar",
			},
		})
		assert.EqualValues(t, handlers.handlers[0].(*testHandler).ListMetricCalled, 2)

		verifyMetricSeriesNotExists(t, promRegistry)
	})

	t.Run("Should not remove metrics series with LabelsContext without namespace", func(t *testing.T) {

		promRegistry := prometheus.NewRegistry()
		opts, _ := ParseContextOptions(Options{"labelsContext": "source_pod,destination_pod"})
		handlers := initHandlers(t, opts, promRegistry, log)

		handlers.ProcessFlow(context.TODO(), flow1)
		handlers.ProcessFlow(context.TODO(), flow2)
		assert.EqualValues(t, handlers.handlers[0].(*testHandler).ProcessCalled, 2)

		verifyMetricSeriesExists(t, promRegistry, 2)

		handlers.ProcessPodDeletion(&slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "foo-123",
				Namespace: "foo",
			},
		})
		assert.EqualValues(t, handlers.handlers[0].(*testHandler).ListMetricCalled, 1)

		verifyMetricSeriesExists(t, promRegistry, 2)

		handlers.ProcessPodDeletion(&slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "bar-123",
				Namespace: "bar",
			},
		})
		assert.EqualValues(t, handlers.handlers[0].(*testHandler).ListMetricCalled, 2)

		verifyMetricSeriesExists(t, promRegistry, 2)
	})

}

func initHandlers(t *testing.T, opts *ContextOptions, promRegistry *prometheus.Registry, log *logrus.Logger) *Handlers {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "test",
		Name:      "events",
	}, opts.GetLabelNames())
	promRegistry.MustRegister(counter)

	r := NewRegistry(log)

	handler := &testHandler{}
	handler.ContextOptions = opts
	handler.counter = counter

	r.Register("test", &testPlugin{handler: handler})

	handlers, err := r.ConfigureHandlers(nil, Map{"test": Options{}})
	assert.EqualValues(t, err, nil)
	assert.EqualValues(t, len(handlers.handlers), 1)
	assert.EqualValues(t, handlers.handlers[0].(*testHandler).InitCalled, 1)
	return handlers
}

func verifyMetricSeriesExists(t *testing.T, promRegistry *prometheus.Registry, expectedCount int) {
	metricFamilies, err := promRegistry.Gather()
	require.NoError(t, err)
	require.Len(t, metricFamilies, 1)
	assert.Equal(t, "test_events", *metricFamilies[0].Name)
	require.Len(t, metricFamilies[0].Metric, expectedCount)
}

func verifyMetricSeriesNotExists(t *testing.T, promRegistry *prometheus.Registry) {
	metricFamilies, err := promRegistry.Gather()
	require.NoError(t, err)
	require.Len(t, metricFamilies, 0)
}
