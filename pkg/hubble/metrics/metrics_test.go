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
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
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
		deletedEndpoint := &types.CiliumEndpoint{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name: "name",
			},
		}
		EnabledMetrics = []api.NamedHandler{}
		endpointDeletionHandler = &CiliumEndpointDeletionHandler{
			gracefulPeriod: 10 * time.Millisecond,
			queue:          workqueue.NewTypedDelayingQueue[*types.CiliumEndpoint](),
		}

		ProcessCiliumEndpointDeletion(deletedEndpoint)

		received, _ := endpointDeletionHandler.queue.Get()
		assert.Equal(t, deletedEndpoint, received)

		endpointDeletionHandler.queue.ShutDown()
	})

}

func SetUpTestMetricsServer(reg *prometheus.Registry) *httptest.Server {
	srv := httptest.NewServer(nil)
	InitMetricsServerHandler(srv.Config, reg, false)
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
		assert.True(t, reflect.DeepEqual(*m.MetricConfig, *(names[m.Name])))
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
	var parser expfmt.TextParser
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
