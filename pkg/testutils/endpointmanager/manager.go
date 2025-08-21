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

type TestEndpointManager struct{}

func (*TestEndpointManager) Subscribe(s endpointmanager.Subscriber)   {}
func (*TestEndpointManager) Unsubscribe(s endpointmanager.Subscriber) {}
func (*TestEndpointManager) UpdatePolicyMaps(ctx context.Context, notifyWg *sync.WaitGroup) *sync.WaitGroup {
	return new(sync.WaitGroup)
}
func (*TestEndpointManager) RegenerateAllEndpoints(regenMetadata *regeneration.ExternalRegenerationMetadata) *sync.WaitGroup {
	return nil
}
func (*TestEndpointManager) TriggerRegenerateAllEndpoints() {}
func (*TestEndpointManager) WaitForEndpointsAtPolicyRev(ctx context.Context, rev uint64) error {
	return nil
}
func (*TestEndpointManager) OverrideEndpointOpts(om option.OptionMap)   {}
func (*TestEndpointManager) InitHostEndpointLabels(ctx context.Context) {}
func (*TestEndpointManager) UpdatePolicy(idsToRegen *set.Set[identity.NumericIdentity], fromRev, toRev uint64) {
}

func (*TestEndpointManager) Lookup(id string) (*endpoint.Endpoint, error)           { return nil, nil }
func (*TestEndpointManager) LookupCiliumID(id uint16) *endpoint.Endpoint            { return nil }
func (*TestEndpointManager) LookupCNIAttachmentID(id string) *endpoint.Endpoint     { return nil }
func (*TestEndpointManager) LookupIPv4(ipv4 string) *endpoint.Endpoint              { return nil }
func (*TestEndpointManager) LookupIPv6(ipv6 string) *endpoint.Endpoint              { return nil }
func (*TestEndpointManager) LookupIP(ip netip.Addr) (ep *endpoint.Endpoint)         { return nil }
func (*TestEndpointManager) LookupCEPName(name string) (ep *endpoint.Endpoint)      { return nil }
func (*TestEndpointManager) GetEndpointsByPodName(name string) []*endpoint.Endpoint { return nil }
func (*TestEndpointManager) GetEndpointsByContainerID(containerID string) []*endpoint.Endpoint {
	return nil
}
func (*TestEndpointManager) GetEndpoints() []*endpoint.Endpoint { return nil }
func (*TestEndpointManager) GetEndpointList(params endpointapi.GetEndpointParams) []*models.Endpoint {
	return nil
}
func (*TestEndpointManager) EndpointExists(id uint16) bool          { return false }
func (*TestEndpointManager) GetHostEndpoint() *endpoint.Endpoint    { return nil }
func (*TestEndpointManager) HostEndpointExists() bool               { return false }
func (*TestEndpointManager) GetIngressEndpoint() *endpoint.Endpoint { return nil }
func (*TestEndpointManager) IngressEndpointExists() bool            { return false }

func (*TestEndpointManager) AddEndpoint(ep *endpoint.Endpoint) (err error) { return nil }
func (*TestEndpointManager) RestoreEndpoint(ep *endpoint.Endpoint) error   { return nil }
func (*TestEndpointManager) UpdateReferences(ep *endpoint.Endpoint) error  { return nil }
func (*TestEndpointManager) RemoveEndpoint(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error {
	return nil
}

func (*TestEndpointManager) RunK8sCiliumEndpointSync(ep *endpoint.Endpoint, hr cell.Health) {}
func (*TestEndpointManager) DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint)               {}
