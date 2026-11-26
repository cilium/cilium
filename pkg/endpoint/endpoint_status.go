// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/api/v1/models"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
)

func (e *Endpoint) getEndpointNetworking(logger *slog.Logger, mdlNetworking *models.EndpointNetworking) (networking *cilium_v2.EndpointNetworking) {
	if mdlNetworking == nil {
		return nil
	}
	networking = &cilium_v2.EndpointNetworking{
		Addressing: make(cilium_v2.AddressPairList, len(mdlNetworking.Addressing)),
	}

	ln, err := e.localNodeStore.Get(context.Background())
	if err != nil {
		logging.Fatal(e.logger.Load(), "failed to retrieve local node")
	}

	networking.NodeIP = node.GetCiliumEndpointNodeIP(ln)

	for i, pair := range mdlNetworking.Addressing {
		networking.Addressing[i] = &cilium_v2.AddressPair{
			IPV4: pair.IPv4,
			IPV6: pair.IPv6,
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

	logger := e.getLogger()

	svcAccount := ""
	var workload *cilium_v2.EndpointWorkload
	if pod := e.GetPod(); pod != nil {
		svcAccount = pod.Spec.ServiceAccountName
		if workloadMeta, workloadTypeMeta, ok := utils.GetWorkloadMetaFromPod(pod); ok {
			workload = &cilium_v2.EndpointWorkload{
				Name: workloadMeta.Name,
				Kind: workloadTypeMeta.Kind,
			}
		}
	}

	ln, err := e.localNodeStore.Get(context.TODO())
	if err != nil {
		logging.Fatal(logger, "getLocalNode: unexpected error", logfields.Error, err)
	}

	status := &cilium_v2.EndpointStatus{
		ID:                  int64(e.ID),
		ExternalIdentifiers: e.getModelEndpointIdentitiersRLocked(),
		Identity:            &cilium_v2.EndpointIdentity{ID: int64(e.SecurityIdentity.ID)},
		Networking:          e.getEndpointNetworking(logger, e.getModelNetworkingRLocked()),
		State:               compressEndpointState(e.getModelCurrentStateRLocked()),
		Encryption:          cilium_v2.EncryptionSpec{Key: int(node.GetEndpointEncryptKeyIndex(ln, e.wgConfig.Enabled(), e.ipsecConfig.Enabled()))},
		NamedPorts:          e.getNamedPortsModel(),
		ServiceAccount:      svcAccount,
		Workload:            workload,
	}

	return status
}
