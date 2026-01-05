// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodeipam

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	ctrlRuntime "sigs.k8s.io/controller-runtime"

	"github.com/cilium/cilium/operator/pkg/lbipam"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/nodeipamconfig"
)

var Cell = cell.Module(
	"nodeipam",
	"Node-IPAM",

	nodeipamconfig.Cell,
	cell.Invoke(registerNodeSvcLBReconciler),
)

type nodeipamCellParams struct {
	cell.In

	Logger             *slog.Logger
	Clientset          k8sClient.Clientset
	CtrlRuntimeManager ctrlRuntime.Manager
	Config             nodeipamconfig.NodeIPAMConfig
	SharedConfig       lbipam.SharedConfig
}

func registerNodeSvcLBReconciler(params nodeipamCellParams) error {
	if !params.Clientset.IsEnabled() || !params.Config.IsEnabled() {
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
