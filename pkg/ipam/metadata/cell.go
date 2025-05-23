// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"ipam-metadata-manager",
	"Provides IPAM metadata",

	cell.Provide(newIPAMMetadataManager),
)

type managerParams struct {
	cell.In

	Logger       *slog.Logger
	DaemonConfig *option.DaemonConfig
	DB           *statedb.DB
	Pods         statedb.Table[k8s.LocalPod]
	Namespaces   statedb.Table[k8s.Namespace]
}

func newIPAMMetadataManager(params managerParams) Manager {
	if params.DaemonConfig.IPAM != ipamOption.IPAMMultiPool {
		return &defaultIPPoolManager{}
	}

	manager := &manager{
		logger:     params.Logger,
		db:         params.DB,
		namespaces: params.Namespaces,
		pods:       params.Pods,
	}

	return manager
}

type defaultIPPoolManager struct{}

var _ Manager = &defaultIPPoolManager{}

func (n *defaultIPPoolManager) GetIPPoolForPod(owner string, family ipam.Family) (pool string, err error) {
	return option.Config.IPAMDefaultIPPool, nil
}
