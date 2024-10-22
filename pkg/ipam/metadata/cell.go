// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/ipam"
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

	Lifecycle    cell.Lifecycle
	DaemonConfig *option.DaemonConfig

	NamespaceResource resource.Resource[*slim_core_v1.Namespace]
	PodResource       k8s.LocalPodResource
}

func newIPAMMetadataManager(params managerParams) Manager {
	if params.DaemonConfig.IPAM != ipamOption.IPAMMultiPool {
		return &defaultIPPoolManager{}
	}

	manager := &manager{
		namespaceResource: params.NamespaceResource,
		podResource:       params.PodResource,
	}
	params.Lifecycle.Append(manager)

	return manager
}

type defaultIPPoolManager struct{}

var _ Manager = &defaultIPPoolManager{}

func (n *defaultIPPoolManager) GetIPPoolForPod(owner string, family ipam.Family) (pool string, err error) {
	return option.Config.IPAMDefaultIPPool, nil
}
