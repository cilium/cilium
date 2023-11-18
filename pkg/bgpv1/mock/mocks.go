// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"context"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"

	v1 "k8s.io/api/core/v1"
	k8sLabels "k8s.io/apimachinery/pkg/labels"
	v1listers "k8s.io/client-go/listers/core/v1"
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

var _ agent.BGPRouterManager = (*MockBGPRouterManager)(nil)

type MockBGPRouterManager struct {
	ConfigurePeers_   func(ctx context.Context, policy *v2alpha1.CiliumBGPPeeringPolicy, ciliumNode *v2.CiliumNode) error
	GetPeers_         func(ctx context.Context) ([]*models.BgpPeer, error)
	GetRoutes_        func(ctx context.Context, params restapi.GetBgpRoutesParams) ([]*models.BgpRoute, error)
	GetRoutePolicies_ func(ctx context.Context, params restapi.GetBgpRoutePoliciesParams) ([]*models.BgpRoutePolicy, error)
	Stop_             func()
}

func (m *MockBGPRouterManager) ConfigurePeers(ctx context.Context, policy *v2alpha1.CiliumBGPPeeringPolicy, ciliumNode *v2.CiliumNode) error {
	return m.ConfigurePeers_(ctx, policy, ciliumNode)
}

func (m *MockBGPRouterManager) GetPeers(ctx context.Context) ([]*models.BgpPeer, error) {
	return m.GetPeers_(ctx)
}

func (m *MockBGPRouterManager) GetRoutes(ctx context.Context, params restapi.GetBgpRoutesParams) ([]*models.BgpRoute, error) {
	return m.GetRoutes_(ctx, params)
}

func (m *MockBGPRouterManager) GetRoutePolicies(ctx context.Context, params restapi.GetBgpRoutePoliciesParams) ([]*models.BgpRoutePolicy, error) {
	return m.GetRoutePolicies_(ctx, params)
}

func (m *MockBGPRouterManager) Stop() {
	m.Stop_()
}
