// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"ipam-metadata-manager",
	"Provides IPAM metadata",

	cell.Provide(newIPAMMetadataManager),
)

type managerParams struct {
	cell.In

	Lifecycle    hive.Lifecycle
	DaemonConfig *option.DaemonConfig

	NamespaceResource resource.Resource[*slim_core_v1.Namespace]
	PodResource       k8s.LocalPodResource
}

func newIPAMMetadataManager(params managerParams) *Manager {
	if params.DaemonConfig.IPAM != ipamOption.IPAMMultiPool {
		return nil
	}

	manager := &Manager{
		namespaceResource: params.NamespaceResource,
		podResource:       params.PodResource,
	}
	params.Lifecycle.Append(manager)

	return manager
}
