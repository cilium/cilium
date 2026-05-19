// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package testendpointmanager provides a shared mock implementation of the
// endpointmanager.EndpointManager interface for use in tests.
package testendpointmanager

import (
	"context"
	"net/netip"
	"sync"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/api/v1/models"
	endpointapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/option"
)

// MockEndpointManager is a mock implementation of endpointmanager.EndpointManager
// for use in unit tests. Most methods panic by default with a few exceptions.
// Tests embed *MockEndpointManager in a local type to override additional
// methods. Add additional mock implementations here if required.
type MockEndpointManager struct {
	Endpoints []*endpoint.Endpoint
}

var (
	_ endpointmanager.EndpointManager              = (*MockEndpointManager)(nil)
	_ endpointmanager.EndpointsLookup              = (*MockEndpointManager)(nil)
	_ endpointmanager.EndpointsModify              = (*MockEndpointManager)(nil)
	_ endpointmanager.EndpointResourceSynchronizer = (*MockEndpointManager)(nil)
)

// NewMockEndpointManager returns a MockEndpointManager with no endpoints and
// every panic-by-default method left unimplemented.
func NewMockEndpointManager() *MockEndpointManager {
	return &MockEndpointManager{}
}

// EndpointsLookup

func (*MockEndpointManager) Lookup(id string) (*endpoint.Endpoint, error) {
	panic("MockEndpointManager.Lookup not implemented")
}

func (*MockEndpointManager) LookupCiliumID(id uint16) *endpoint.Endpoint {
	panic("MockEndpointManager.LookupCiliumID not implemented")
}

func (*MockEndpointManager) LookupCNIAttachmentID(id string) *endpoint.Endpoint {
	panic("MockEndpointManager.LookupCNIAttachmentID not implemented")
}

func (*MockEndpointManager) LookupIPv4(ipv4 string) *endpoint.Endpoint {
	panic("MockEndpointManager.LookupIPv4 not implemented")
}

func (*MockEndpointManager) LookupIPv6(ipv6 string) *endpoint.Endpoint {
	panic("MockEndpointManager.LookupIPv6 not implemented")
}

func (*MockEndpointManager) LookupIP(ip netip.Addr) *endpoint.Endpoint {
	panic("MockEndpointManager.LookupIP not implemented")
}

func (*MockEndpointManager) LookupCEPName(name string) *endpoint.Endpoint {
	panic("MockEndpointManager.LookupCEPName not implemented")
}

func (*MockEndpointManager) GetEndpointsByPodName(name string) []*endpoint.Endpoint {
	panic("MockEndpointManager.GetEndpointsByPodName not implemented")
}

func (*MockEndpointManager) GetEndpointsByContainerID(containerID string) []*endpoint.Endpoint {
	panic("MockEndpointManager.GetEndpointsByContainerID not implemented")
}

func (*MockEndpointManager) GetEndpointsByServiceAccount(namespace string, serviceAccount string) []*endpoint.Endpoint {
	panic("MockEndpointManager.GetEndpointsByServiceAccount not implemented")
}

func (m *MockEndpointManager) GetEndpointsByNamespace(namespace string) []*endpoint.Endpoint {
	var eps []*endpoint.Endpoint
	for _, ep := range m.Endpoints {
		if ep.K8sNamespace == namespace {
			eps = append(eps, ep)
		}
	}
	return eps
}

func (m *MockEndpointManager) GetEndpoints() []*endpoint.Endpoint {
	return m.Endpoints
}

func (*MockEndpointManager) GetEndpointList(params endpointapi.GetEndpointParams) []*models.Endpoint {
	panic("MockEndpointManager.GetEndpointList not implemented")
}

func (*MockEndpointManager) EndpointExists(id uint16) bool {
	panic("MockEndpointManager.EndpointExists not implemented")
}

func (*MockEndpointManager) GetHostEndpoint() *endpoint.Endpoint {
	panic("MockEndpointManager.GetHostEndpoint not implemented")
}

func (*MockEndpointManager) HostEndpointExists() bool {
	panic("MockEndpointManager.HostEndpointExists not implemented")
}

func (*MockEndpointManager) GetIngressEndpoint() *endpoint.Endpoint {
	panic("MockEndpointManager.GetIngressEndpoint not implemented")
}

func (*MockEndpointManager) IngressEndpointExists() bool {
	panic("MockEndpointManager.IngressEndpointExists not implemented")
}

// EndpointsModify

func (*MockEndpointManager) AddEndpoint(ep *endpoint.Endpoint) error {
	panic("MockEndpointManager.AddEndpoint not implemented")
}

func (*MockEndpointManager) RestoreEndpoint(ep *endpoint.Endpoint) error {
	panic("MockEndpointManager.RestoreEndpoint not implemented")
}

func (*MockEndpointManager) UpdateReferences(ep *endpoint.Endpoint) error {
	panic("MockEndpointManager.UpdateReferences not implemented")
}

func (*MockEndpointManager) RemoveEndpoint(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error {
	panic("MockEndpointManager.RemoveEndpoint not implemented")
}

// EndpointResourceSynchronizer

func (*MockEndpointManager) RunK8sCiliumEndpointSync(ep *endpoint.Endpoint, hr cell.Health) {
	panic("MockEndpointManager.RunK8sCiliumEndpointSync not implemented")
}

func (*MockEndpointManager) DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint) {
	panic("MockEndpointManager.DeleteK8sCiliumEndpointSync not implemented")
}

// EndpointManager

func (*MockEndpointManager) Subscribe(s endpointmanager.Subscriber) {}

func (*MockEndpointManager) Unsubscribe(s endpointmanager.Subscriber) {}

func (*MockEndpointManager) UpdatePolicyMaps(ctx context.Context) error {
	panic("MockEndpointManager.UpdatePolicyMaps not implemented")
}

func (*MockEndpointManager) RegenerateAllEndpoints(regenMetadata *regeneration.ExternalRegenerationMetadata) *sync.WaitGroup {
	panic("MockEndpointManager.RegenerateAllEndpoints not implemented")
}

func (*MockEndpointManager) TriggerRegenerateAllEndpoints() {
	panic("MockEndpointManager.TriggerRegenerateAllEndpoints not implemented")
}

func (*MockEndpointManager) WaitForEndpointsAtPolicyRev(ctx context.Context, rev uint64) error {
	panic("MockEndpointManager.WaitForEndpointsAtPolicyRev not implemented")
}

func (*MockEndpointManager) OverrideEndpointOpts(om option.OptionMap) {
	panic("MockEndpointManager.OverrideEndpointOpts not implemented")
}

func (*MockEndpointManager) InitHostEndpointLabels(ctx context.Context) {
	panic("MockEndpointManager.InitHostEndpointLabels not implemented")
}

func (*MockEndpointManager) UpdatePolicy(idsToRegen *set.Set[identity.NumericIdentity], fromRev, toRev uint64) {
	panic("MockEndpointManager.UpdatePolicy not implemented")
}
