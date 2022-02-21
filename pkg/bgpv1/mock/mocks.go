// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"context"

	v1 "k8s.io/api/core/v1"
	k8sLabels "k8s.io/apimachinery/pkg/labels"
	v1listers "k8s.io/client-go/listers/core/v1"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v2alpha1listers "github.com/cilium/cilium/pkg/k8s/client/listers/cilium.io/v2alpha1"
)

var _ v1listers.NodeLister = (*MockNodeLister)(nil)

type MockNodeLister struct {
	List_ func(selector k8sLabels.Selector) (ret []*v1.Node, err error)
	Get_  func(name string) (*v1.Node, error)
	v1listers.NodeListerExpansion
}

func (m *MockNodeLister) List(selector k8sLabels.Selector) (ret []*v1.Node, err error) {
	return m.List_(selector)
}

func (m *MockNodeLister) Get(name string) (*v1.Node, error) {
	return m.Get_(name)
}

var _ v2alpha1listers.CiliumBGPPeeringPolicyLister = (*MockCiliumBGPPeeringPolicyLister)(nil)

type MockCiliumBGPPeeringPolicyLister struct {
	List_ func(selector k8sLabels.Selector) (ret []*v2alpha1.CiliumBGPPeeringPolicy, err error)
	Get_  func(name string) (*v2alpha1.CiliumBGPPeeringPolicy, error)
	v2alpha1listers.CiliumBGPPeeringPolicyListerExpansion
}

func (m *MockCiliumBGPPeeringPolicyLister) List(selector k8sLabels.Selector) (ret []*v2alpha1.CiliumBGPPeeringPolicy, err error) {
	return m.List_(selector)
}

func (m *MockCiliumBGPPeeringPolicyLister) Get(name string) (*v2alpha1.CiliumBGPPeeringPolicy, error) {
	return m.Get_(name)
}

var _ agent.BGPRouterManager = (*MockBGPRouterManager)(nil)

type MockBGPRouterManager struct {
	ConfigurePeers_ func(ctx context.Context, policy *v2alpha1.CiliumBGPPeeringPolicy, cstate *agent.ControlPlaneState) error
}

func (m *MockBGPRouterManager) ConfigurePeers(ctx context.Context, policy *v2alpha1.CiliumBGPPeeringPolicy, cstate *agent.ControlPlaneState) error {
	return m.ConfigurePeers_(ctx, policy, cstate)
}
