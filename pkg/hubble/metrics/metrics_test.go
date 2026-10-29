// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metrics

import (
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/util/workqueue"

	dto "github.com/prometheus/client_model/go"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

func TestInitializedMetrics(t *testing.T) {
	t.Run("Should send pod removal to delayed delivery queue", func(t *testing.T) {
		previousEnabledMetrics := EnabledMetrics
		previousEndpointDeletionHandler := endpointDeletionHandler
		t.Cleanup(func() {
			endpointDeletionHandler.queue.ShutDown()
			EnabledMetrics = previousEnabledMetrics
			endpointDeletionHandler = previousEndpointDeletionHandler
		})

		deletedEndpoint := &types.CiliumEndpoint{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name: "name",
			},
		}
		EnabledMetrics = nil
		endpointDeletionHandler = &CiliumEndpointDeletionHandler{
			gracefulPeriod: 10 * time.Millisecond,
			queue:          workqueue.NewTypedDelayingQueue[*types.CiliumEndpoint](),
		}

		ProcessCiliumEndpointDeletion(deletedEndpoint)

		require.Eventually(t, func() bool {
			return endpointDeletionHandler.queue.Len() == 1
		}, time.Second, 10*time.Millisecond)
		received, _ := endpointDeletionHandler.queue.Get()
		assert.Equal(t, deletedEndpoint, received)
	})

}

func TestDynamicMetricsCleanupOnEndpointDeletion(t *testing.T) {
	dfp, reg := newTestDynamicFlowProcessor(t)

	processDropFlow(t, dfp, "deleted-source", "live-destination")
	processDropFlow(t, dfp, "live-source", "deleted-destination")
	processDropFlow(t, dfp, "live-source", "live-destination")
	processDropFlow(t, dfp, "live-source", "live-destination")

	require.Equal(t, map[string]float64{
		"test/deleted-source->test/live-destination": 1,
		"test/live-source->test/deleted-destination": 1,
		"test/live-source->test/live-destination":    2,
	}, gatheredDropMetrics(t, reg))

	require.NoError(t, ProcessCiliumEndpointDeletion(&types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{Name: "deleted-source", Namespace: "test"},
	}))
	require.NoError(t, ProcessCiliumEndpointDeletion(&types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{Name: "deleted-destination", Namespace: "test"},
	}))

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, map[string]float64{
			"test/live-source->test/live-destination": 2,
		}, gatheredDropMetrics(c, reg))
	}, time.Second, 10*time.Millisecond)
}

func TestStaticMetricsCleanupOnEndpointDeletion(t *testing.T) {
	previousEnabledMetrics := EnabledMetrics
	previousEndpointDeletionHandler := endpointDeletionHandler
	t.Cleanup(func() {
		endpointDeletionHandler.queue.ShutDown()
		EnabledMetrics = previousEnabledMetrics
		endpointDeletionHandler = previousEndpointDeletionHandler
	})

	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, InitMetrics(
		hivetest.Logger(t),
		reg,
		api.ParseStaticMetricsConfig([]string{"drop:sourceContext=pod;destinationContext=pod"}),
		grpc_prometheus.NewServerMetrics(),
	))
	endpointDeletionHandler.gracefulPeriod = 0

	processor := NewStaticFlowProcessor(hivetest.Logger(t), EnabledMetrics)
	processDropFlow(t, processor, "deleted-source", "live-destination")
	processDropFlow(t, processor, "live-source", "live-destination")
	require.Equal(t, map[string]float64{
		"test/deleted-source->test/live-destination": 1,
		"test/live-source->test/live-destination":    1,
	}, gatheredDropMetrics(t, reg))

	require.NoError(t, ProcessCiliumEndpointDeletion(&types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{Name: "deleted-source", Namespace: "test"},
	}))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, map[string]float64{
			"test/live-source->test/live-destination": 1,
		}, gatheredDropMetrics(c, reg))
	}, time.Second, 10*time.Millisecond)
}

func TestDynamicMetricsCleanupUsesReplacementHandlers(t *testing.T) {
	dfp, reg := newTestDynamicFlowProcessor(t)

	cleanup := endpointDeletionHandler.cleanup
	dequeued := make(chan struct{})
	release := make(chan struct{})
	released := false
	releaseCleanup := func() {
		if !released {
			close(release)
			released = true
		}
	}
	t.Cleanup(releaseCleanup)
	endpointDeletionHandler.cleanup = func(endpoint *types.CiliumEndpoint) {
		close(dequeued)
		<-release
		cleanup(endpoint)
	}

	require.NoError(t, ProcessCiliumEndpointDeletion(&types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{Name: "deleted-source", Namespace: "test"},
	}))
	select {
	case <-dequeued:
	case <-time.After(time.Second):
		releaseCleanup()
		t.Fatal("endpoint deletion was not dequeued")
	}

	config := api.Config{Metrics: []*api.MetricConfig{{
		Name: "drop",
		ContextOptionConfigs: []*api.ContextOptionConfig{
			{Name: "sourceContext", Values: []string{"pod"}},
			{Name: "destinationContext", Values: []string{"pod"}},
		},
	}}}
	dfp.onConfigReload(t.Context(), 0, api.Config{})
	dfp.onConfigReload(t.Context(), 0, config)

	processDropFlow(t, dfp, "deleted-source", "live-destination")
	processDropFlow(t, dfp, "live-source", "live-destination")
	require.Equal(t, map[string]float64{
		"test/deleted-source->test/live-destination": 1,
		"test/live-source->test/live-destination":    1,
	}, gatheredDropMetrics(t, reg))
	releaseCleanup()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, map[string]float64{
			"test/live-source->test/live-destination": 1,
		}, gatheredDropMetrics(c, reg))
	}, time.Second, 10*time.Millisecond)
}

func newTestDynamicFlowProcessor(t *testing.T) (*DynamicFlowProcessor, *prometheus.Registry) {
	t.Helper()

	previousEnabledMetrics := EnabledMetrics
	previousEndpointDeletionHandler := endpointDeletionHandler
	t.Cleanup(func() {
		if endpointDeletionHandler != nil {
			endpointDeletionHandler.queue.ShutDown()
		}
		EnabledMetrics = previousEnabledMetrics
		endpointDeletionHandler = previousEndpointDeletionHandler
	})
	EnabledMetrics = nil

	configPath := filepath.Join(t.TempDir(), "metrics.yaml")
	err := os.WriteFile(configPath, []byte(`metrics:
- name: drop
  contextOptions:
  - name: sourceContext
    values: [pod]
  - name: destinationContext
    values: [pod]
`), 0o600)
	require.NoError(t, err)

	reg := prometheus.NewPedanticRegistry()
	dfp := NewDynamicFlowProcessor(reg, hivetest.Logger(t), configPath)
	t.Cleanup(func() {
		require.NoError(t, dfp.Stop())
	})
	endpointDeletionHandler.gracefulPeriod = 0
	return dfp, reg
}

func processDropFlow(t *testing.T, processor FlowProcessor, sourcePod, destinationPod string) {
	t.Helper()
	err := processor.ProcessFlow(t.Context(), &pb.Flow{
		EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
		L4: &pb.Layer4{
			Protocol: &pb.Layer4_TCP{TCP: &pb.TCP{}},
		},
		Source:         &pb.Endpoint{Namespace: "test", PodName: sourcePod},
		Destination:    &pb.Endpoint{Namespace: "test", PodName: destinationPod},
		Verdict:        pb.Verdict_DROPPED,
		DropReason:     uint32(pb.DropReason_POLICY_DENIED),
		DropReasonDesc: pb.DropReason_POLICY_DENIED,
	})
	require.NoError(t, err)
}

func gatheredDropMetrics(t require.TestingT, reg *prometheus.Registry) map[string]float64 {
	metricFamilies, err := reg.Gather()
	require.NoError(t, err)

	metrics := make(map[string]float64)
	for _, family := range metricFamilies {
		if family.GetName() != "hubble_drop_total" {
			continue
		}
		for _, metric := range family.Metric {
			labels := make(map[string]string)
			for _, label := range metric.Label {
				labels[label.GetName()] = label.GetValue()
			}
			metrics[labels["source"]+"->"+labels["destination"]] = metric.GetCounter().GetValue()
		}
	}
	return metrics
}

func SetUpTestMetricsServer(reg *prometheus.Registry) *httptest.Server {
	srv := httptest.NewServer(ServerHandler(reg, false))
	return srv
}

func ConfigureAndFetchMetrics(t *testing.T, testName string, metricCfg []string, exportedMetrics map[string][]string) {
	t.Run(testName, func(t *testing.T) {
		reg := prometheus.NewPedanticRegistry()
		srv := SetUpTestMetricsServer(reg)
		defer srv.Close()

		grpcMetrics := grpc_prometheus.NewServerMetrics()
		InitMetrics(
			hivetest.Logger(t),
			reg,
			api.ParseStaticMetricsConfig(metricCfg),
			grpcMetrics)
		t.Cleanup(endpointDeletionHandler.queue.ShutDown)

		flow := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
			L4: &pb.Layer4{
				Protocol: &pb.Layer4_TCP{
					TCP: &pb.TCP{},
				},
			},
			Source:      &pb.Endpoint{Namespace: "foo"},
			Destination: &pb.Endpoint{Namespace: "bar"},
			Verdict:     pb.Verdict_DROPPED,
			DropReason:  uint32(pb.DropReason_POLICY_DENIED),
		}

		var err error
		for _, nh := range EnabledMetrics {
			err = errors.Join(err, nh.Handler.ProcessFlow(t.Context(), flow))
		}
		require.NoError(t, err)

		resp, err := http.Get("http://" + srv.Listener.Addr().String() + "/metrics")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		assertMetricsFromServer(t, resp.Body, exportedMetrics)
	})
}

func TestHubbleServerStandalone(t *testing.T) {
	ConfigureAndFetchMetrics(
		t,
		"IsMetricServedDropWithOptions",
		[]string{"drop:destinationContext=namespace;sourceContext=namespace", "flow:labelsContext=source_ip"},
		map[string][]string{
			"hubble_drop_total":            {"destination", "protocol", "reason", "source"},
			"hubble_flows_processed_total": {"protocol", "source_ip", "subtype", "type", "verdict"}})
}

func TestReadMetricConfigFromCM(t *testing.T) {
	watcher := metricConfigWatcher{configFilePath: "testdata/valid_metric_config_drop_flow.yaml", cfgStore: make(map[string]*api.MetricConfig)}
	cfg, _, _, err := watcher.readConfig()
	require.NoError(t, err)

	expectedConfigs := []api.MetricConfig{
		{
			Name: "drop",
			ContextOptionConfigs: []*api.ContextOptionConfig{
				{
					Name:   "labelsContext",
					Values: []string{"source_namespace", "source_pod", "destination_pods"},
				},
			},
			IncludeFilters: []*pb.FlowFilter{
				{
					SourcePod: []string{"allow/src_pod"},
				},
				{
					DestinationPod: []string{"allow/dst_pod"},
				},
			},
			ExcludeFilters: []*pb.FlowFilter{},
		},
		{
			Name: "flow",
			ContextOptionConfigs: []*api.ContextOptionConfig{
				{
					Name:   "destinationContext",
					Values: []string{"dns", "ip"},
				},
			},
			IncludeFilters: []*pb.FlowFilter{},
			ExcludeFilters: []*pb.FlowFilter{},
		},
	}

	for i := range expectedConfigs {
		assertMetricConfig(t, expectedConfigs[i], *cfg.Metrics[i])
	}

	// Attempt to re-register drop handler with fewer labels should fail.
	watcher.resetCfgPath("testdata/valid_metric_config_drop_fewer_labels.yaml")
	_, _, _, err = watcher.readConfig()
	require.EqualError(t, err, "invalid yaml config file: metric config validation failed - label set cannot be changed without restarting Prometheus. metric: drop")

	// Attempt to register metric handlers with missing names should fail.
	watcher.resetCfgPath("testdata/invalid_config_missing_name.yaml")
	_, _, _, err = watcher.readConfig()
	require.EqualError(t, err, "invalid yaml config file: metric config validation failed - missing metric name at: 0\nmetric config validation failed - missing metric name at: 1")
}

func assertMetricConfig(t *testing.T, expected, actual api.MetricConfig) {
	assert.Equal(t, expected.Name, actual.Name)

	assert.Len(t, actual.ContextOptionConfigs, len(expected.ContextOptionConfigs))
	for i, c := range expected.ContextOptionConfigs {
		assert.Len(t, actual.ContextOptionConfigs[i].Values, len(expected.ContextOptionConfigs[i].Values))
		assert.Equal(t, expected.ContextOptionConfigs[i].Name, actual.ContextOptionConfigs[i].Name)
		for j, s := range c.Values {
			assert.Equal(t, expected.ContextOptionConfigs[i].Values[j], s)
		}
	}

	assert.Len(t, actual.IncludeFilters, len(expected.IncludeFilters))
	for i := range expected.IncludeFilters {
		assert.Equal(t, expected.IncludeFilters[i].String(), actual.IncludeFilters[i].String())
	}

	assert.Len(t, actual.ExcludeFilters, len(expected.ExcludeFilters))
	for i := range expected.ExcludeFilters {
		assert.Equal(t, expected.ExcludeFilters[i].String(), actual.ExcludeFilters[i].String())
	}
}

func TestHandlersUpdatedInDfpOnConfigChange(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	dfp := DynamicFlowProcessor{registry: reg, logger: slog.Default()}
	assert.Nil(t, dfp.Metrics)

	// Handlers: +drop
	watcher := metricConfigWatcher{configFilePath: "testdata/valid_metric_config_drop.yaml", cfgStore: make(map[string]*api.MetricConfig)}
	cfg, _, _, err := watcher.readConfig()
	require.NoError(t, err)

	dfp.onConfigReload(t.Context(), 0, *cfg)
	assertHandlersInDfp(t, &dfp, cfg)

	// Handlers: =drop, +flow
	watcher.resetCfgPath("testdata/valid_metric_config_drop_flow.yaml")
	cfg, _, _, err = watcher.readConfig()
	require.NoError(t, err)

	dfp.onConfigReload(t.Context(), 0, *cfg)
	assertHandlersInDfp(t, &dfp, cfg)

	// Handlers: -drop, =flow
	watcher.resetCfgPath("testdata/valid_metric_config_flow.yaml")
	cfg, _, _, err = watcher.readConfig()
	require.NoError(t, err)

	dfp.onConfigReload(t.Context(), 0, *cfg)
	assertHandlersInDfp(t, &dfp, cfg)

	// Handlers: -drop, =flow+filter
	watcher.resetCfgPath("testdata/valid_metric_config_flow_with_filter.yaml")
	cfg, _, _, err = watcher.readConfig()
	require.NoError(t, err)

	dfp.onConfigReload(t.Context(), 0, *cfg)
	assertHandlersInDfp(t, &dfp, cfg)

	// Handlers: =flow~filter
	watcher.resetCfgPath("testdata/valid_metric_config_flow_with_filter_2.yaml")
	cfg, _, _, err = watcher.readConfig()
	require.NoError(t, err)

	dfp.onConfigReload(t.Context(), 0, *cfg)
	assertHandlersInDfp(t, &dfp, cfg)
}

func assertHandlersInDfp(t *testing.T, dfp *DynamicFlowProcessor, cfg *api.Config) {
	names := cfg.GetMetricNames()
	assert.Len(t, dfp.Metrics, len(names))
	for _, m := range dfp.Metrics {
		_, ok := names[m.Name]
		assert.True(t, ok)
		assert.Equal(t, *(names[m.Name]), *m.MetricConfig)
	}
}

func TestMetricReRegisterAndCollect(t *testing.T) {
	// Handlers: +drop
	watcher := metricConfigWatcher{configFilePath: "testdata/valid_metric_config_drop.yaml", cfgStore: make(map[string]*api.MetricConfig)}
	cfg, _, _, err := watcher.readConfig()
	require.NoError(t, err)

	reg := prometheus.NewPedanticRegistry()
	dfp := DynamicFlowProcessor{registry: reg, logger: slog.Default()}
	dfp.onConfigReload(t.Context(), 0, *cfg)

	flow1 := &pb.Flow{
		EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
		L4: &pb.Layer4{
			Protocol: &pb.Layer4_TCP{
				TCP: &pb.TCP{},
			},
		},
		Source:         &pb.Endpoint{Namespace: "allow", PodName: "src_pod"},
		Destination:    &pb.Endpoint{Namespace: "allow", PodName: "dst_pod"},
		Verdict:        pb.Verdict_DROPPED,
		DropReason:     uint32(pb.DropReason_POLICY_DENIED),
		DropReasonDesc: pb.DropReason_POLICY_DENIED,
	}

	_, errs := dfp.OnDecodedFlow(t.Context(), flow1)
	assert.NoError(t, errs)

	metricFamilies, err := reg.Gather()
	require.NoError(t, err)
	assert.NotNil(t, metricFamilies)
	assertGatheredDrops(t, metricFamilies)

	// Read in empty config.
	watcher.resetCfgPath("testdata/valid_empty_metric_cfg.yaml")
	cfg, _, _, err = watcher.readConfig()
	require.NoError(t, err)

	dfp.onConfigReload(t.Context(), 0, *cfg)
	assert.NoError(t, errs)

	// The existing drop metrics should be removed after the handler is deregistered.
	metricFamilies, err = reg.Gather()
	require.NoError(t, err)
	assert.Nil(t, metricFamilies)

	// Re-register drop handler with same config and collect metrics.
	watcher.resetCfgPath("testdata/valid_metric_config_drop.yaml")
	cfg, _, _, err = watcher.readConfig()
	require.NoError(t, err)

	dfp.onConfigReload(t.Context(), 0, *cfg)
	assert.NoError(t, errs)

	_, errs = dfp.OnDecodedFlow(t.Context(), flow1)
	assert.NoError(t, errs)

	metricFamilies, err = reg.Gather()
	require.NoError(t, err)
	assert.NotNil(t, metricFamilies)
	assertGatheredDrops(t, metricFamilies)
}

func assertGatheredDrops(t *testing.T, metricFamilies []*dto.MetricFamily) {
	assert.Equal(t, "hubble_drop_total", *metricFamilies[0].Name)
	require.Len(t, metricFamilies[0].Metric, 1)
	metric := metricFamilies[0].Metric[0]

	assert.Equal(t, "destination_pod", *metric.Label[0].Name)
	assert.Equal(t, "dst_pod", *metric.Label[0].Value)

	assert.Equal(t, "protocol", *metric.Label[1].Name)
	assert.Equal(t, "TCP", *metric.Label[1].Value)

	assert.Equal(t, "reason", *metric.Label[2].Name)
	assert.Equal(t, "POLICY_DENIED", *metric.Label[2].Value)

	assert.Equal(t, "source_namespace", *metric.Label[3].Name)
	assert.Equal(t, "allow", *metric.Label[3].Value)

	assert.Equal(t, "source_pod", *metric.Label[4].Name)
	assert.Equal(t, "src_pod", *metric.Label[4].Value)

	assert.Equal(t, 1., *metric.Counter.Value)
}

func ConfigureAndFetchDynamicMetrics(t *testing.T, testName string, exportedMetrics map[string][]string) {
	t.Run(testName, func(t *testing.T) {
		reg := prometheus.NewPedanticRegistry()
		srv := SetUpTestMetricsServer(reg)
		defer srv.Close()

		// Handlers: +drop, +flow
		watcher := metricConfigWatcher{configFilePath: "testdata/valid_metric_config_drop_flow.yaml", cfgStore: make(map[string]*api.MetricConfig)}
		cfg, _, _, err := watcher.readConfig()
		require.NoError(t, err)

		dfp := DynamicFlowProcessor{registry: reg, logger: slog.Default()}
		dfp.onConfigReload(t.Context(), 0, *cfg)

		flow1 := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
			L4: &pb.Layer4{
				Protocol: &pb.Layer4_TCP{
					TCP: &pb.TCP{},
				},
			},
			Source:         &pb.Endpoint{Namespace: "allow", PodName: "src_pod"},
			Destination:    &pb.Endpoint{Namespace: "allow", PodName: "dst_pod"},
			Verdict:        pb.Verdict_DROPPED,
			DropReason:     uint32(pb.DropReason_POLICY_DENIED),
			DropReasonDesc: pb.DropReason_POLICY_DENIED,
		}

		_, errs := dfp.OnDecodedFlow(t.Context(), flow1)
		assert.NoError(t, errs)

		resp, err := http.Get("http://" + srv.Listener.Addr().String() + "/metrics")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		assertMetricsFromServer(t, resp.Body, exportedMetrics)
	})
}

func TestHubbleServerWithDynamicMetrics(t *testing.T) {
	ConfigureAndFetchDynamicMetrics(
		t,
		"IsMetricServedDropWithOptions",
		map[string][]string{
			"hubble_drop_total":            {"destination_pod", "protocol", "reason", "source_namespace", "source_pod"},
			"hubble_flows_processed_total": {"destination", "protocol", "subtype", "type", "verdict"}})
}

func assertMetricsFromServer(t *testing.T, in io.Reader, exportedMetrics map[string][]string) {
	var parser = expfmt.NewTextParser(model.LegacyValidation)
	mfMap, err := parser.TextToMetricFamilies(in)
	if err != nil {
		log.Fatal(err)
	}

	for metricName, metricFamily := range mfMap {
		_, ok := exportedMetrics[metricName]
		assert.True(t, ok)

		labels := []string{}
		for _, labelPair := range metricFamily.Metric[0].Label {
			labels = append(labels, *(labelPair.Name))
		}
		sort.Strings(labels)
		require.Equal(t, exportedMetrics[metricName], labels)
	}
}
