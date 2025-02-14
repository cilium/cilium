// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodeipam

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	ctrlRuntime "sigs.k8s.io/controller-runtime"

	"github.com/cilium/cilium/operator/pkg/lbipam"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

var Cell = cell.Module(
	"nodeipam",
	"Node-IPAM",

	cell.Provide(func(r nodeIpamConfig) NodeIPAMConfig { return r }),
	cell.Config(nodeIpamConfig{}),
	cell.Invoke(registerNodeSvcLBReconciler),
)

type nodeipamCellParams struct {
	cell.In

	Logger             *slog.Logger
	Clientset          k8sClient.Clientset
	CtrlRuntimeManager ctrlRuntime.Manager
	Config             nodeIpamConfig
	SharedConfig       lbipam.SharedConfig
}

type nodeIpamConfig struct {
	EnableNodeIPAM bool
}

func (r nodeIpamConfig) IsEnabled() bool {
	return r.EnableNodeIPAM
}

type NodeIPAMConfig interface {
	IsEnabled() bool
}

func (r nodeIpamConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-node-ipam", r.EnableNodeIPAM, "Enable Node IPAM")
}

func registerNodeSvcLBReconciler(params nodeipamCellParams) error {
	if !params.Clientset.IsEnabled() || !params.Config.EnableNodeIPAM {
		return nil
	}

	if err := newNodeSvcLBReconciler(
		params.CtrlRuntimeManager,
		params.Logger,
		params.SharedConfig.DefaultLBServiceIPAM == lbipam.DefaultLBClassNodeIPAM,
	).SetupWithManager(params.CtrlRuntimeManager); err != nil {
		return fmt.Errorf("Failed to register NodeSvcLBReconciler: %w", err)
	}

	return nil
}
