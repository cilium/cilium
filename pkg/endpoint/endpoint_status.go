// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"slices"

	"github.com/cilium/cilium/api/v1/models"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/node"
)

func getEndpointIdentity(mdlIdentity *models.Identity) (identity *cilium_v2.EndpointIdentity) {
	if mdlIdentity == nil {
		return
	}
	identity = &cilium_v2.EndpointIdentity{
		ID: mdlIdentity.ID,
	}

	identity.Labels = make([]string, len(mdlIdentity.Labels))
	copy(identity.Labels, mdlIdentity.Labels)
	slices.Sort(identity.Labels)
	return
}

func getEndpointNetworking(mdlNetworking *models.EndpointNetworking) (networking *cilium_v2.EndpointNetworking) {
	if mdlNetworking == nil {
		return nil
	}
	networking = &cilium_v2.EndpointNetworking{
		Addressing: make(cilium_v2.AddressPairList, len(mdlNetworking.Addressing)),
	}

	networking.NodeIP = node.GetCiliumEndpointNodeIP()

	for i, pair := range mdlNetworking.Addressing {
		networking.Addressing[i] = &cilium_v2.AddressPair{
			IPV4: pair.IPV4,
			IPV6: pair.IPV6,
		}
	}

	networking.Addressing.Sort()
	return
}

func compressEndpointState(state models.EndpointState) string {
	switch state {
	case models.EndpointStateRestoring, models.EndpointStateWaitingDashToDashRegenerate,
		models.EndpointStateRegenerating, models.EndpointStateReady,
		models.EndpointStateDisconnecting, models.EndpointStateDisconnected:
		return string(models.EndpointStateReady)
	}

	return string(state)
}

// GetCiliumEndpointStatus creates a cilium_v2.EndpointStatus of an endpoint.
// See cilium_v2.EndpointStatus for a detailed explanation of each field.
func (e *Endpoint) GetCiliumEndpointStatus() *cilium_v2.EndpointStatus {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	status := &cilium_v2.EndpointStatus{
		ID:                  int64(e.ID),
		ExternalIdentifiers: e.getModelEndpointIdentitiersRLocked(),
		Identity:            getEndpointIdentity(identitymodel.CreateModel(e.SecurityIdentity)),
		Networking:          getEndpointNetworking(e.getModelNetworkingRLocked()),
		State:               compressEndpointState(e.getModelCurrentStateRLocked()),
		Encryption:          cilium_v2.EncryptionSpec{Key: int(node.GetEndpointEncryptKeyIndex())},
		NamedPorts:          e.getNamedPortsModel(),
	}

	return status
}
