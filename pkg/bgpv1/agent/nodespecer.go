// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/stream"

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
	NodeResource       *LocalNodeResource
	CiliumNodeResource *LocalCiliumNodeResource
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
	nodeResource *LocalNodeResource

	currentNode *corev1.Node
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
	errChan := make(chan error, 2)
	nodeChan := stream.ToChannel[resource.Event[*corev1.Node]](ctx, errChan, s.nodeResource)
	for event := range nodeChan {
		event.Handle(
			nil,
			func(k resource.Key, n *corev1.Node) error {
				s.currentNode = n
				s.signaler.Event(struct{}{})
				return nil
			},
			nil,
		)
	}

	return <-errChan
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
	nodeResource *LocalCiliumNodeResource

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
	errChan := make(chan error, 2)
	nodeChan := stream.ToChannel[resource.Event[*cilium_api_v2.CiliumNode]](ctx, errChan, s.nodeResource)
	for event := range nodeChan {
		event.Handle(
			nil,
			func(k resource.Key, cn *ciliumv2.CiliumNode) error {
				s.currentNode = cn
				s.signaler.Event(struct{}{})
				return nil
			},
			nil,
		)
	}

	return <-errChan
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

// LocalNodeResource is a resource.Resource[*corev1.Node] but one which will only stream updates for the node object
// associated with the node we are currently running on.
type LocalNodeResource struct {
	resource.Resource[*v1.Node]
}

func NewLocalNodeResource(lc hive.Lifecycle, cs client.Clientset) (*LocalNodeResource, error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*corev1.NodeList](cs.CoreV1().Nodes())
	lw = utils.ListerWatcherWithFields(lw, fields.ParseSelectorOrDie("metadata.name="+nodeTypes.GetName()))
	return &LocalNodeResource{Resource: resource.New[*corev1.Node](lc, lw)}, nil
}

// LocalCiliumNodeResource is a resource.Resource[*cilium_api_v2.Node] but one which will only stream updates for the
// CiliumNode object associated with the node we are currently running on.
type LocalCiliumNodeResource struct {
	resource.Resource[*cilium_api_v2.CiliumNode]
}

func NewLocalCiliumNodeResource(lc hive.Lifecycle, cs client.Clientset) (*LocalCiliumNodeResource, error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNodeList](cs.CiliumV2().CiliumNodes())
	lw = utils.ListerWatcherWithFields(lw, fields.ParseSelectorOrDie("metadata.name="+nodeTypes.GetName()))
	return &LocalCiliumNodeResource{Resource: resource.New[*cilium_api_v2.CiliumNode](lc, lw)}, nil
}
