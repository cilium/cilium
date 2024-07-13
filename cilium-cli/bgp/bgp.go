// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgp

import (
	"context"
	"fmt"
	"io"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/k8s"
)

// Parameters contains options for CLI
type Parameters struct {
	CiliumNamespace  string
	AgentPodSelector string
	NodeName         string
	Writer           io.Writer
	WaitDuration     time.Duration
	Output           string
}

// Status is used to get bgp state from cilium agents
type Status struct {
	client     *k8s.Client
	params     Parameters
	ciliumPods []*corev1.Pod
}

// NewStatus returns new bgp.Status struct
func NewStatus(client *k8s.Client, p Parameters) *Status {
	return &Status{
		client: client,
		params: p,
	}
}

// initTargetCiliumPods stores cilium agent pods in the status.ciliumPods.
// If node selector option is specified then only that nodes' cilium-agent
// pod is stored else all cilium-agents in the cluster are stored.
func (s *Status) initTargetCiliumPods(ctx context.Context) error {
	opts := metav1.ListOptions{LabelSelector: s.params.AgentPodSelector}
	if s.params.NodeName != "" {
		opts.FieldSelector = fmt.Sprintf("spec.nodeName=%s", s.params.NodeName)
	}

	ciliumPods, err := s.client.ListPods(ctx, s.params.CiliumNamespace, opts)
	if err != nil {
		return fmt.Errorf("unable to list Cilium pods: %w", err)
	}

	for _, ciliumPod := range ciliumPods.Items {
		s.ciliumPods = append(s.ciliumPods, ciliumPod.DeepCopy())
	}
	return nil
}
