// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/cilium-cli/k8s"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Parameters contains options for CLI
type Parameters struct {
	CiliumNamespace         string
	CiliumOperatorNamespace string
	AgentPodSelector        string
	OperatorPodSelector     string
	CiliumOperatorCommand   string
	NodeName                string
	OperatorNodeName        string
	WaitDuration            time.Duration
	Output                  string
	Outputfile              string
	MetricsDirectory        string
	Repo                    string
	Commit                  string
	GHStepSummaryAnchor     bool
}

type Feature struct {
	client *k8s.Client
	params Parameters
}

func NewFeatures(client *k8s.Client, p Parameters) *Feature {
	return &Feature{
		client: client,
		params: p,
	}
}

// fetchCiliumPods returns slice of cilium agent pods.
// If option NodeName is specified then only that nodes' cilium-agent
// pod is returned else all cilium-agents in the cluster are returned.
func (s *Feature) fetchCiliumPods(ctx context.Context) ([]corev1.Pod, error) {
	opts := metav1.ListOptions{LabelSelector: s.params.AgentPodSelector}
	if s.params.NodeName != "" {
		opts.FieldSelector = fmt.Sprintf("spec.nodeName=%s", s.params.NodeName)
	}

	pods, err := s.client.ListPods(ctx, s.params.CiliumNamespace, opts)
	if err != nil {
		return nil, fmt.Errorf("unable to list Cilium pods: %w", err)
	}
	return pods.Items, nil
}

// fetchCiliumOperator returns slice of cilium operator pods.
// If option NodeName is specified then only that nodes' cilium-operator
// pod is returned else all cilium-agents in the cluster are returned.
func (s *Feature) fetchCiliumOperator(ctx context.Context) ([]corev1.Pod, error) {
	opts := metav1.ListOptions{LabelSelector: s.params.OperatorPodSelector}
	if s.params.NodeName != "" {
		opts.FieldSelector = fmt.Sprintf("spec.nodeName=%s", s.params.OperatorNodeName)
	}

	pods, err := s.client.ListPods(ctx, s.params.CiliumOperatorNamespace, opts)
	if err != nil {
		return nil, fmt.Errorf("unable to list Cilium pods: %w", err)
	}
	return pods.Items, nil
}
