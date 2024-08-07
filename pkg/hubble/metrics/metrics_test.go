// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/util/workqueue"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

func TestUninitializedMetrics(t *testing.T) {
	enabledMetrics = nil
	endpointDeletionHandler = nil
	ProcessFlow(context.TODO(), &pb.Flow{})
	ProcessCiliumEndpointDeletion(&types.CiliumEndpoint{})
}

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
		log := logrus.New()

		reg := prometheus.NewPedanticRegistry()
		srv := SetUpTestMetricsServer(reg)
		defer srv.Close()

		grpcMetrics := grpc_prometheus.NewServerMetrics()
		InitMetrics(
			reg,
			api.ParseMetricList(metricCfg),
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

		var parser expfmt.TextParser
		mfMap, err := parser.TextToMetricFamilies(resp.Body)
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
			require.Equal(t, labels, exportedMetrics[metricName])
		}
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
