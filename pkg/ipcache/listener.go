// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"net"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
)

// CacheModification represents the type of operation performed upon IPCache.
type CacheModification string

const (
	// Upsert represents Upsertion into IPCache.
	Upsert CacheModification = "Upsert"

	// Delete represents deletion of an entry in IPCache.
	Delete CacheModification = "Delete"
)

// IPIdentityMappingListener represents a component that is interested in
// learning about IP to Identity mapping events.
type IPIdentityMappingListener interface {
	// OnIPIdentityCacheChange will be called whenever there the state of the
	// IPCache has changed. If an existing CIDR->ID mapping is updated, then
	// oldID is not nil; otherwise it is nil.
	// hostIP is the IP address of the location of the cidr.
	// hostIP is optional and may only be non-nil for an Upsert modification.
	// k8sMeta contains the Kubernetes pod namespace and name behind the IP
	// and may be nil.
	OnIPIdentityCacheChange(modType CacheModification, cidrCluster cmtypes.PrefixCluster, oldHostIP, newHostIP net.IP,
		oldID *Identity, newID Identity, encryptKey uint8, nodeID uint16, k8sMeta *K8sMetadata)

	// OnIPIdentityCacheGC will be called to sync other components which are
	// reliant upon the IPIdentityCache with the IPIdentityCache.
	OnIPIdentityCacheGC()
}
