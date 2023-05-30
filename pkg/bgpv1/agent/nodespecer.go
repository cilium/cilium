// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/option"

	"github.com/cilium/workerpool"
)

// nodeSpecer is an abstraction which allows us to mock/fake out the local node resource during testing.
type nodeSpecer interface {
	Annotations() (map[string]string, error)
	Labels() (map[string]string, error)
	PodCIDRs() ([]string, error)
}

type localNodeStoreSpecerParams struct {
	cell.In

	Lifecycle          hive.Lifecycle
	Config             *option.DaemonConfig
	NodeResource       k8s.LocalNodeResource
	CiliumNodeResource k8s.LocalCiliumNodeResource
	Signaler           Signaler
}

// NewNodeSpecer constructs a new nodeSpecer and registers it in the hive lifecycle
func NewNodeSpecer(params localNodeStoreSpecerParams) (nodeSpecer, error) {
	if !params.Config.BGPControlPlaneEnabled() {
		return nil, nil
	}

	switch params.Config.IPAM {
	case ipamOption.IPAMClusterPoolV2, ipamOption.IPAMClusterPool:
		cns := &ciliumNodeSpecer{
			nodeResource: params.CiliumNodeResource,
			signaler:     params.Signaler,
		}
		params.Lifecycle.Append(cns)
		return cns, nil

	case ipamOption.IPAMKubernetes:
		kns := &kubernetesNodeSpecer{
			nodeResource: params.NodeResource,
			signaler:     params.Signaler,
		}
		params.Lifecycle.Append(kns)
		return kns, nil

	default:
		return nil, fmt.Errorf("BGP Control Plane doesn't support current IPAM-mode: '%s'", params.Config.IPAM)
	}
}

type kubernetesNodeSpecer struct {
	nodeResource k8s.LocalNodeResource

	currentNode *slim_corev1.Node
	workerpool  *workerpool.WorkerPool
	signaler    Signaler
}

func (s *kubernetesNodeSpecer) Start(_ hive.HookContext) error {
	s.workerpool = workerpool.New(1)
	s.workerpool.Submit("kubernetes-node-specer-run", s.run)

	return nil
}

func (s *kubernetesNodeSpecer) Stop(ctx hive.HookContext) error {
	doneChan := make(chan struct{})

	go func() {
		s.workerpool.Close()
		close(doneChan)
	}()

	select {
	case <-doneChan:
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func (s *kubernetesNodeSpecer) run(ctx context.Context) error {
	for event := range s.nodeResource.Events(ctx) {
		if event.Kind == resource.Upsert && event.Object != nil {
			s.currentNode = event.Object
			s.signaler.Event(struct{}{})
		}

		event.Done(nil)
	}

	return nil
}

func (s *kubernetesNodeSpecer) Annotations() (map[string]string, error) {
	if s.currentNode == nil {
		return nil, errors.New("annotations of current node not yet available")
	}

	return s.currentNode.Annotations, nil
}

func (s *kubernetesNodeSpecer) Labels() (map[string]string, error) {
	if s.currentNode == nil {
		return nil, errors.New("labels of current node not yet available")
	}

	return s.currentNode.Labels, nil
}

func (s *kubernetesNodeSpecer) PodCIDRs() ([]string, error) {
	if s.currentNode == nil {
		return nil, errors.New("pod ciders of current node not yet available")
	}

	if s.currentNode.Spec.PodCIDRs != nil {
		return s.currentNode.Spec.PodCIDRs, nil
	}
	if s.currentNode.Spec.PodCIDR != "" {
		return []string{s.currentNode.Spec.PodCIDR}, nil
	}
	return []string{}, nil
}

type ciliumNodeSpecer struct {
	nodeResource k8s.LocalCiliumNodeResource

	currentNode *ciliumv2.CiliumNode
	workerpool  *workerpool.WorkerPool
	signaler    Signaler
}

func (s *ciliumNodeSpecer) Start(_ hive.HookContext) error {
	s.workerpool = workerpool.New(1)
	s.workerpool.Submit("cilium-node-specer-run", s.run)

	return nil
}

func (s *ciliumNodeSpecer) Stop(ctx hive.HookContext) error {
	doneChan := make(chan struct{})

	go func() {
		s.workerpool.Close()
		close(doneChan)
	}()

	select {
	case <-doneChan:
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func (s *ciliumNodeSpecer) run(ctx context.Context) error {
	for event := range s.nodeResource.Events(ctx) {
		if event.Kind == resource.Upsert && event.Object != nil {
			s.currentNode = event.Object
			s.signaler.Event(struct{}{})
		}

		event.Done(nil)
	}

	return nil
}

func (s *ciliumNodeSpecer) Annotations() (map[string]string, error) {
	if s.currentNode == nil {
		return nil, errors.New("annotations of current node not yet available")
	}

	return s.currentNode.Annotations, nil
}

func (s *ciliumNodeSpecer) Labels() (map[string]string, error) {
	if s.currentNode == nil {
		return nil, errors.New("labels of current node not yet available")
	}

	return s.currentNode.Labels, nil
}

func (s *ciliumNodeSpecer) PodCIDRs() ([]string, error) {
	if s.currentNode == nil {
		return nil, errors.New("pod ciders of current node not yet available")
	}

	if s.currentNode.Spec.IPAM.PodCIDRs != nil {
		return s.currentNode.Spec.IPAM.PodCIDRs, nil
	}

	return []string{}, nil
}
