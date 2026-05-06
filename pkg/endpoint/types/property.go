// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

const (
	// PropertyFakeEndpoint marks the endpoint as being "fake". By "fake" it
	// means that it doesn't have any datapath bpf programs regenerated.
	PropertyFakeEndpoint = "property-fake-endpoint"

	// PropertyAtHostNS is used for endpoints that are reached via the host networking
	// namespace, but have their own IP(s) from the node's pod CIDR range
	PropertyAtHostNS = "property-at-host-network-namespace"

	// PropertyWithouteBPFDatapath marks the endpoint that doesn't contain a
	// eBPF datapath program.
	PropertyWithouteBPFDatapath = "property-without-bpf-endpoint"

	// PropertySkipBPFPolicy will mark the endpoint to skip ebpf
	// policy regeneration.
	PropertySkipBPFPolicy = "property-skip-bpf-policy"

	// PropertySkipBPFRegeneration will mark the endpoint to skip ebpf
	// regeneration.
	PropertySkipBPFRegeneration = "property-skip-bpf-regeneration"

	// PropertyCEPOwner will be able to store the CEP owner for this endpoint.
	PropertyCEPOwner = "property-cep-owner"

	// PropertyCEPName contains the CEP name for this endpoint.
	PropertyCEPName = "property-cep-name"

	// PropertySkipMasqueradeV4 will mark the endpoint to skip IPv4 masquerade.
	PropertySkipMasqueradeV4 = "property-skip-masquerade-v4"
	// PropertySkipMasqueradeV6 will mark the endpoint to skip IPv6 masquerade.
	PropertySkipMasqueradeV6 = "property-skip-masquerade-v6"
	// Property RTInfo describes the endpoint's RTInfo encoding.
	PropertyRTInfo = "property-rt-info"
)
