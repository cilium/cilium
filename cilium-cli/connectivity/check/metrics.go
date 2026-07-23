// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"
	"fmt"
	"io"
	"net/http"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"github.com/cilium/cilium/pkg/k8s/portforward"
)

// metricsURLFormat is the path format to retrieve the metrics on the
const metricsURLFormat = "http://localhost:%d/metrics"

// promMetricsPerSource holds all the metrics per source name per node.
// sources e.g.: cilium agent, cilium operator, hubble
type promMetricsPerSource map[string]promMetricsPerNode

// promMetricsPerNode stores for each node Prometheus Metrics.
type promMetricsPerNode map[string]promMetricsFamily

// promMetricsFamily holds Prometheus metrics per metric name.
type promMetricsFamily map[string]*dto.MetricFamily

// collectPrometheusMetrics retrieves the Prometheus metrics by
// port-forwarding the Prometheus port of each source pod and calling /metrics endpoint.
func (a *Action) collectPrometheusMetrics(source MetricsSource) (promMetricsPerNode, error) {
	m := make(promMetricsPerNode)

	// Retrieve metrics for all Cilium pods.
	for _, pod := range source.Pods {
		metrics, err := a.collectMetricsForPod(pod, source.Port)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve prometheus metrics for pod %s: %w", pod.Name(), err)
		}

		// Store metrics per node for the ease of use when validating.
		m[pod.NodeName()] = metrics
	}

	return m, nil
}

// collectPrometheusMetricsForNode retrieves all the metrics for a source on a particular node.
func (a *Action) collectPrometheusMetricsForNode(source MetricsSource, node string) (promMetricsFamily, error) {
	for _, pod := range source.Pods {
		if pod.NodeName() == node {
			metrics, err := a.collectMetricsForPod(pod, source.Port)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve prometheus metrics for pod %s on node %s: %w", pod.Name(), pod.NodeName(), err)
			}
			return metrics, nil
		}
	}

	return promMetricsFamily{}, nil
}

// collectMetricsForPod retrieves the metrics for one pod.
func (a *Action) collectMetricsForPod(pod Pod, port string) (promMetricsFamily, error) {
	return fetchPodMetrics(a.test.ctx, pod, port)
}

// fetchPodMetrics port-forwards to the given pod's Prometheus port and returns
// its parsed metrics. It is decoupled from Action so that Scenarios can read
// metrics outside of the per-action before/after validation flow (see
// ConnectivityTest.SumCiliumAgentMetric).
func fetchPodMetrics(ct *ConnectivityTest, pod Pod, port string) (promMetricsFamily, error) {
	// The context is in charge if closing the port-forward when it is cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := portforward.PortForwardParameters{
		Namespace:  pod.Namespace(),
		Pod:        pod.NameWithoutNamespace(),
		Ports:      []string{fmt.Sprintf(":%s", port)},
		Addresses:  nil, // default is localhost
		OutWriters: portforward.OutWriters{Out: &debugWriter{ct: ct}, ErrOut: &warnWriter{ct: ct}},
	}

	// Call the k8s dialer to port forward,
	// a random port will be generated to avoid conflict.
	res, err := pod.K8sClient.PortForward(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("failed to port forward: %w", err)
	}

	// Call the metrics path on the retrieved local port.
	url := fmt.Sprintf(metricsURLFormat, res.ForwardedPorts[0].Local)
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve metrics: %w", err)
	}
	defer resp.Body.Close()

	// Convert the text output into handy format metrics.
	metrics, err := parseMetrics(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse metrics: %w", err)
	}

	return metrics, nil
}

// parseMetrics transforms the response from the call to prometheus metric endpoint
// into a dto model MetricFamily.
func parseMetrics(reader io.Reader) (promMetricsFamily, error) {
	var parser = expfmt.NewTextParser(model.LegacyValidation)
	mf, err := parser.TextToMetricFamilies(reader)
	if err != nil {
		return nil, err
	}
	return mf, nil
}

// metricsIncrease verifies for all the metrics that the values increased.
func metricsIncrease(mf1, mf2 *dto.MetricFamily) error {
	metrics1 := mf1.GetMetric()
	metrics2 := mf2.GetMetric()

	// Absent initial metric means it's zero, check that after metric is non-zero.
	if mf1 == nil && mf2 != nil {
		for _, m2 := range metrics2 {
			if m2.GetCounter() == nil {
				return fmt.Errorf("metric %s is not a Counter: %v", mf2.GetName(), mf2)
			}

			if val := m2.GetCounter().GetValue(); val == 0.0 {
				return fmt.Errorf("metric %s did not increase as expected, value 1 was assumed zero: %f and value 2: %f", mf2.GetName(), 0.0, val)
			}
		}
		return nil
	}

	if len(metrics1) != len(metrics2) {
		return fmt.Errorf("metric %s has different length metrics 1: %d and metrics 2: %d", mf1.GetName(), len(metrics1), len(metrics2))
	}

	for i := range metrics1 {
		if metrics1[i].GetCounter() == nil {
			return fmt.Errorf("metric %s is not a Counter: %v", mf1.GetName(), metrics1[i])
		}
		if metrics2[i].GetCounter() == nil {
			return fmt.Errorf("metric %s is not a Counter: %v", mf1.GetName(), metrics2[i])
		}

		value1 := metrics1[i].GetCounter().GetValue()
		value2 := metrics2[i].GetCounter().GetValue()
		if value1 >= value2 {
			return fmt.Errorf("metric %s did not increase as expected, value 1: %f and value 2: %f", mf1.GetName(), value1, value2)
		}
	}

	return nil
}

// SumCiliumAgentMetric returns the sum of the counter samples of the named
// metric exposed by the Cilium agent running on the given node, restricted to
// samples whose labels are a superset of the provided labels (an empty/nil
// labels map matches every sample). It is meant for aggregate before/after
// assertions in Scenarios, e.g. counting DNS proxy verdicts across a batch of
// requests.
//
// It returns (0, nil) when the Cilium agent does not expose Prometheus metrics
// (e.g. metrics are disabled), so callers can treat that as "skip the metric
// assertion". It returns an error only when metrics are exposed but could not
// be retrieved.
func (ct *ConnectivityTest) SumCiliumAgentMetric(node, name string, labels map[string]string) (float64, error) {
	source := ct.CiliumAgentMetrics()
	if source.IsEmpty() {
		return 0, nil
	}

	var agentPod *Pod
	for i := range source.Pods {
		if source.Pods[i].NodeName() == node {
			agentPod = &source.Pods[i]
			break
		}
	}
	if agentPod == nil {
		return 0, fmt.Errorf("no Cilium agent pod found on node %q", node)
	}

	metrics, err := fetchPodMetrics(ct, *agentPod, source.Port)
	if err != nil {
		return 0, err
	}

	return sumCounterMetric(metrics[name], labels), nil
}

// sumCounterMetric sums the values of all counter samples in mf whose labels
// are a superset of the provided labels.
func sumCounterMetric(mf *dto.MetricFamily, labels map[string]string) float64 {
	if mf == nil {
		return 0
	}
	var sum float64
	for _, m := range mf.GetMetric() {
		if m.GetCounter() == nil {
			continue
		}
		if metricHasLabels(m, labels) {
			sum += m.GetCounter().GetValue()
		}
	}
	return sum
}

// metricHasLabels reports whether the metric sample carries every label in the
// provided map with the exact value.
func metricHasLabels(m *dto.Metric, labels map[string]string) bool {
	for key, want := range labels {
		found := false
		for _, lp := range m.GetLabel() {
			if lp.GetName() == key && lp.GetValue() == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
