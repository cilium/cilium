// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	ciliumBPFMetadataListenerFilterName = "cilium.bpf_metadata"
)

// listenerRequiresNPDS returns true if the listener carries a cilium.bpf_metadata
// listener filter that will start an NPDS (Network Policy Discovery Service) client.
//
// For the listener to start the NPDS client it must have a correctly configured
// bpf_root (matching the system's BPF filesystem root)
//
// Corresponding proxy logic: https://github.com/cilium/proxy/blob/4054ac22c6338f0372aac9f23a7cda99e8ebf6da/cilium/bpf_metadata.cc#L273
func listenerRequiresNPDS(listener *envoy_config_listener.Listener) bool {
	for _, lf := range listener.GetListenerFilters() {
		if lf.GetName() != ciliumBPFMetadataListenerFilterName || lf.GetTypedConfig() == nil {
			continue
		}

		var bpfMeta cilium.BpfMetadata
		err := lf.GetTypedConfig().UnmarshalTo(&bpfMeta)

		if err == nil && bpfMeta.GetBpfRoot() == bpf.BPFFSRoot() {
			return true
		}
	}
	return false
}
