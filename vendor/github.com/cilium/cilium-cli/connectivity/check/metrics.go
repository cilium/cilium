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

	"github.com/cilium/cilium-cli/k8s"
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
	// The context is in charge if closing the port-forward when it is cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := k8s.PortForwardParameters{
		Namespace:  pod.Namespace(),
		Pod:        pod.NameWithoutNamespace(),
		Ports:      []string{fmt.Sprintf(":%s", port)},
		Addresses:  nil, // default is localhost
		OutWriters: k8s.OutWriters{Out: &debugWriter{ct: a.test.ctx}, ErrOut: &warnWriter{ct: a.test.ctx}},
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
	var parser expfmt.TextParser
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

		value1 := metrics1[i].GetCounter().GetValue() // Here we assume that metrics are of Counter type.
		value2 := metrics2[i].GetCounter().GetValue()
		if value1 >= value2 {
			return fmt.Errorf("metric %s did not increase as expected, value 1: %f and value 2: %f", mf1.GetName(), value1, value2)
		}
	}

	return nil
}
