// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metrics

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/util/workqueue"

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
		enabledMetrics = &api.Handlers{}
		endpointDeletionHandler = &CiliumEndpointDeletionHandler{
			gracefulPeriod: 10 * time.Millisecond,
			queue:          workqueue.NewDelayingQueue(),
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
		enabledMetrics.ProcessFlow(context.TODO(), flow)

		resp, err := http.Get("http://" + srv.Listener.Addr().String() + "/metrics")
		require.Nil(t, err)
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
	watcher := metricConfigWatcher{configFilePath: "testdata/valid_metric_config_2.yaml"}
	cfg, _, _, err := watcher.readConfig()
	require.Nil(t, err)

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
}

func assertMetricConfig(t *testing.T, expected, actual api.MetricConfig) {
	assert.Equal(t, expected.Name, actual.Name)

	assert.Equal(t, len(expected.ContextOptionConfigs), len(actual.ContextOptionConfigs))
	for i, c := range expected.ContextOptionConfigs {
		assert.Equal(t, len(expected.ContextOptionConfigs[i].Values), len(actual.ContextOptionConfigs[i].Values))
		assert.Equal(t, expected.ContextOptionConfigs[i].Name, actual.ContextOptionConfigs[i].Name)
		for j, s := range c.Values {
			assert.Equal(t, expected.ContextOptionConfigs[i].Values[j], s)
		}
	}

	assert.Equal(t, len(expected.IncludeFilters), len(actual.IncludeFilters))
	for i := range expected.IncludeFilters {
		assert.Equal(t, expected.IncludeFilters[i].String(), actual.IncludeFilters[i].String())
	}

	assert.Equal(t, len(expected.ExcludeFilters), len(actual.ExcludeFilters))
	for i := range expected.ExcludeFilters {
		assert.Equal(t, expected.ExcludeFilters[i].String(), actual.ExcludeFilters[i].String())
	}
}

func TestMetricsUpdatedOnConfigChange(t *testing.T) {
	// Handlers: +drop
	watcher := metricConfigWatcher{configFilePath: "testdata/valid_metric_config.yaml"}
	cfg, _, _, err := watcher.readConfig()
	require.Nil(t, err)

	reg := prometheus.NewPedanticRegistry()
	dfp := DynamicFlowProcessor{registry: reg}
	assert.Nil(t, dfp.Metrics)
	dfp.onConfigReload(context.TODO(), false, 0, *cfg)
	assertMetricsConfigured(t, &dfp, cfg)

	// Handlers: =drop, +flow
	watcher = metricConfigWatcher{configFilePath: "testdata/valid_metric_config_2.yaml"}
	cfg, _, _, err = watcher.readConfig()
	require.Nil(t, err)

	dfp.onConfigReload(context.TODO(), false, 0, *cfg)
	assertMetricsConfigured(t, &dfp, cfg)

	// Handlers: -drop, =flow
	watcher = metricConfigWatcher{configFilePath: "testdata/valid_metric_config_3.yaml"}
	cfg, _, _, err = watcher.readConfig()
	require.Nil(t, err)

	dfp.onConfigReload(context.TODO(), false, 0, *cfg)
	assertMetricsConfigured(t, &dfp, cfg)
}

func assertMetricsConfigured(t *testing.T, dfp *DynamicFlowProcessor, cfg *api.Config) {
	names := cfg.GetMetricNames()
	assert.Equal(t, len(names), len(dfp.Metrics.Handlers))
	for _, m := range dfp.Metrics.Handlers {
		_, ok := names[m.Name]
		assert.True(t, ok)
	}
}

func TestDfpProcessFlow(t *testing.T) {
	// Handlers: =drop, +flow
	watcher := metricConfigWatcher{configFilePath: "testdata/valid_metric_config.yaml"}
	cfg, _, _, err := watcher.readConfig()
	require.Nil(t, err)

	reg := prometheus.NewPedanticRegistry()
	dfp := DynamicFlowProcessor{registry: reg}
	dfp.onConfigReload(context.TODO(), false, 0, *cfg)

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

	_, errs := dfp.OnDecodedFlow(context.TODO(), flow1)
	assert.Nil(t, errs)

	metricFamilies, err := reg.Gather()
	require.NoError(t, err)

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

		// Handlers: =drop, +flow
		watcher := metricConfigWatcher{configFilePath: "testdata/valid_metric_config_2.yaml"}
		cfg, _, _, err := watcher.readConfig()
		require.Nil(t, err)

		dfp := DynamicFlowProcessor{registry: reg}
		dfp.onConfigReload(context.TODO(), false, 0, *cfg)

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

		_, errs := dfp.OnDecodedFlow(context.TODO(), flow1)
		assert.Nil(t, errs)

		resp, err := http.Get("http://" + srv.Listener.Addr().String() + "/metrics")
		require.Nil(t, err)
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
		require.NotEmpty(t, ok)

		labels := []string{}
		for _, labelPair := range metricFamily.Metric[0].Label {
			labels = append(labels, *(labelPair.Name))
		}
		sort.Strings(labels)
		require.Equal(t, exportedMetrics[metricName], labels)
	}
}
