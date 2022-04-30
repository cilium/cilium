// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package addressing

// AddressType represents a type of IP address for a node. They are copied
// from k8s.io/api/core/v1/types.go to avoid pulling in a lot of Kubernetes
// imports into this package.s
type AddressType string

const (
	NodeHostName         AddressType = "Hostname"
	NodeExternalIP       AddressType = "ExternalIP"
	NodeInternalIP       AddressType = "InternalIP"
	NodeExternalDNS      AddressType = "ExternalDNS"
	NodeInternalDNS      AddressType = "InternalDNS"
	NodeCiliumInternalIP AddressType = "CiliumInternalIP"
)
