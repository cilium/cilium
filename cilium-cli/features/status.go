// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/cilium-cli/defaults"
)

var (
	cmdMetricsList = []string{"cilium", "metrics", "list", "-p", "cilium_feature", "-o", "json"}
)

// perDeployNodeMetrics maps a deployment name to their node metrics
type perDeployNodeMetrics map[string]perNodeMetrics

// perNodeMetrics maps a node name to their metrics
type perNodeMetrics map[string][]*models.Metric

// PrintFeatureStatus prints encryption status from all/specific cilium agent pods.
func (s *Feature) PrintFeatureStatus(ctx context.Context) error {
	ctx, cancelFn := context.WithTimeout(ctx, s.params.WaitDuration)
	defer cancelFn()

	pods, err := s.fetchCiliumPods(ctx)
	if err != nil {
		return err
	}

	operatorPods, err := s.fetchCiliumOperator(ctx)
	if err != nil {
		return err
	}

	nodeMap, err := s.fetchStatusConcurrently(ctx, pods, s.fetchCiliumFeatureMetricsFromPod)
	if err != nil {
		return err
	}

	operatorNodeMap, err := s.fetchStatusConcurrently(ctx, operatorPods, s.fetchCiliumOperatorFeatureMetricsFromPod)
	if err != nil {
		return err
	}

	w := os.Stdout
	if s.params.Outputfile != "-" {
		w, err = os.Create(s.params.Outputfile)
		if err != nil {
			return err
		}
		defer w.Close()
	}

	switch s.params.Output {
	case "tab":
		w.WriteString("Cilium Operators\n")
		err := printPerNodeFeatureStatus(operatorNodeMap, newTabWriter(w))
		if err != nil {
			return err
		}
		w.WriteString("\nCilium Agents\n")
		return printPerNodeFeatureStatus(nodeMap, newTabWriter(w))
	case "markdown":
		w.WriteString("# Cilium Operators\n")
		err := printPerNodeFeatureStatus(operatorNodeMap, newMarkdownWriter(w))
		if err != nil {
			return err
		}
		w.WriteString("\n# Cilium Agents\n")
		return printPerNodeFeatureStatus(nodeMap, newMarkdownWriter(w))
	case "json":
		pdnm := perDeployNodeMetrics{
			defaults.AgentDaemonSetName:     nodeMap,
			defaults.OperatorDeploymentName: operatorNodeMap,
		}
		return json.NewEncoder(w).Encode(pdnm)
	default:
		return fmt.Errorf("output %s not recognized", s.params.Output)
	}
}

func (s *Feature) fetchStatusConcurrently(ctx context.Context, pods []corev1.Pod, fetcher func(ctx context.Context, pod corev1.Pod) ([]*models.Metric, error)) (perNodeMetrics, error) {
	// res contains data returned from cilium pod
	type res struct {
		nodeName string
		status   []*models.Metric
		err      error
	}
	resCh := make(chan res)
	defer close(resCh)

	// concurrently fetch state from each cilium pod
	for _, pod := range pods {
		go func(ctx context.Context, pod corev1.Pod) {
			st, err := fetcher(ctx, pod)
			resCh <- res{
				nodeName: pod.Spec.NodeName,
				status:   st,
				err:      err,
			}
		}(ctx, pod)
	}

	// read from the channel, on error, store error and continue to next node
	var err error
	data := make(perNodeMetrics)
	for range pods {
		r := <-resCh
		if r.err != nil {
			err = errors.Join(err, r.err)
			continue
		}
		data[r.nodeName] = r.status
	}
	return data, err
}

func (s *Feature) fetchCiliumFeatureMetricsFromPod(ctx context.Context, pod corev1.Pod) ([]*models.Metric, error) {
	output, err := s.client.ExecInPod(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, cmdMetricsList)
	if err != nil {
		return nil, fmt.Errorf("failed to features status from %s: %w", pod.Name, err)
	}
	encStatus, err := nodeStatusFromOutput(output.String())
	if err != nil {
		return nil, fmt.Errorf("failed to features status from %s: %w", pod.Name, err)
	}
	return encStatus, nil
}

func (s *Feature) fetchCiliumOperatorFeatureMetricsFromPod(ctx context.Context, pod corev1.Pod) ([]*models.Metric, error) {
	operatorCmd := s.params.CiliumOperatorCommand
	if operatorCmd == "" {
		operatorCmd = ciliumOperatorBinary(pod)
		if operatorCmd == "" {
			return nil, fmt.Errorf("operator command not found in Cilium Operator pod. Use --operator-container-command to define it")
		}
	}
	cmd := []string{operatorCmd, "metrics", "list", "-p", "cilium_operator_feature", "-o", "json"}
	output, err := s.client.ExecInPod(ctx, pod.Namespace, pod.Name, defaults.OperatorContainerName, cmd)
	if err != nil && !strings.Contains(err.Error(), "level=debug") {
		return []*models.Metric{}, fmt.Errorf("failed to get features status from %s: %w", pod.Name, err)
	}
	encStatus, err := nodeStatusFromOutput(output.String())
	if err != nil {
		return []*models.Metric{}, fmt.Errorf("failed to decode features status from %s: %w", pod.Name, err)
	}
	return encStatus, nil
}

func ciliumOperatorBinary(pod corev1.Pod) string {
	for _, container := range pod.Spec.Containers {
		if container.Name == defaults.OperatorContainerName {
			for _, cmd := range container.Command {
				if strings.Contains(cmd, "cilium-operator") {
					return cmd
				}
			}
		}
	}
	return ""
}

func nodeStatusFromOutput(output string) ([]*models.Metric, error) {
	var encStatus []*models.Metric
	if err := json.Unmarshal([]byte(output), &encStatus); err != nil {
		return []*models.Metric{}, fmt.Errorf("failed to unmarshal json: %w", err)
	}
	return encStatus, nil
}

type statusPrinter interface {
	printHeader(sorted []string) error
	printNode(metricName, labels string, isBinary bool, values map[float64]struct{}, key string, nodesSorted []string, metricsPerNode map[string]map[string]float64)
	end() error
}

// parseNameAndLabels splits the key into name and labels based on the first ";" separator
func parseNameAndLabels(key string) (string, string) {
	if idx := strings.Index(key, ";"); idx != -1 {
		return key[:idx], key[idx+1:]
	}
	return key, ""
}

func printPerNodeFeatureStatus(nodeMap perNodeMetrics, sp statusPrinter) error {
	nodesSorted := slices.Sorted(maps.Keys(nodeMap))

	// Create header with all the nodes' names
	err := sp.printHeader(nodesSorted)
	if err != nil {
		return err
	}

	// map a metric name + labels to a node value
	//   map[name+labels][node-name]value
	metrics := make(map[string]map[string]float64)
	metricNamesLabels := map[string]struct{}{}
	for nodeName, nodeMetrics := range nodeMap {
		for _, metric := range nodeMetrics {
			var orderedLabels []string
			for k, v := range metric.Labels {
				orderedLabels = append(orderedLabels, fmt.Sprintf("%s=%s", k, v))
			}
			slices.Sort(orderedLabels)

			// Generate a unique key based on metric name and labels for each entry
			key := metric.Name
			if len(orderedLabels) != 0 {
				key += ";"
			}
			key += strings.Join(orderedLabels, ";")

			if _, ok := metrics[key]; !ok {
				metrics[key] = make(map[string]float64)
			}
			metrics[key][nodeName] = metric.Value
			metricNamesLabels[key] = struct{}{}
		}
	}

	metricNamesLabelsSorted := slices.Sorted(maps.Keys(metricNamesLabels))

	var previousMetricName string
	var firstMetric bool
	for _, key := range metricNamesLabelsSorted {

		values := make(map[float64]struct{})
		isBinary := true
		for _, node := range nodesSorted {
			value := metrics[key][node]
			values[value] = struct{}{}
			if value != 0 && value != 1 {
				isBinary = false
			}
		}

		metricName, labels := parseNameAndLabels(key)

		if firstMetric || (previousMetricName != metricName) {
			firstMetric = false
			previousMetricName = metricName
		} else {
			previousMetricName = ""
		}
		sp.printNode(previousMetricName, labels, isBinary, values, key, nodesSorted, metrics)

		previousMetricName = metricName
	}

	return sp.end()
}
