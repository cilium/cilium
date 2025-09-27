// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
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
	Logger       *slog.Logger
	DaemonConfig *option.DaemonConfig
	Clientset    k8sClient.Clientset
	DB           *statedb.DB
	Pods         statedb.Table[k8s.LocalPod]
	Namespaces   statedb.Table[k8s.Namespace]
	Jobs         job.Group

	PodIPPoolResource resource.Resource[*api_v2alpha1.CiliumPodIPPool]
}

func newIPAMMetadataManager(params managerParams) Manager {
	if params.DaemonConfig.IPAM != ipamOption.IPAMMultiPool {
		return &defaultIPPoolManager{}
	}

	manager := &manager{
		logger:        params.Logger,
		db:            params.DB,
		namespaces:    params.Namespaces,
		pods:          params.Pods,
		compiledPools: map[string]compiledPool{},
	}

	params.Jobs.Add(job.Observer("ipam-pool-watcher", manager.handlePoolEvent, params.PodIPPoolResource))

	return manager
}

type defaultIPPoolManager struct{}

var _ Manager = &defaultIPPoolManager{}

func (n *defaultIPPoolManager) GetIPPoolForPod(owner string, family ipam.Family) (pool string, err error) {
	return option.Config.IPAMDefaultIPPool, nil
}
