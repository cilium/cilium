// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodeipam

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	ctrlRuntime "sigs.k8s.io/controller-runtime"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/lbipamconfig"
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
	NodeIPAMConfig     nodeipamconfig.NodeIPAMConfig
	LBIPAMConfig       lbipamconfig.Config
}

func registerNodeSvcLBReconciler(params nodeipamCellParams) error {
	if !params.Clientset.IsEnabled() || !params.NodeIPAMConfig.IsEnabled() {
		return nil
	}

	if err := newNodeSvcLBReconciler(
		params.CtrlRuntimeManager,
		params.Logger,
		params.LBIPAMConfig.GetDefaultLBServiceIPAM() == lbipamconfig.DefaultLBClassNodeIPAM,
	).SetupWithManager(params.CtrlRuntimeManager); err != nil {
		return fmt.Errorf("Failed to register NodeSvcLBReconciler: %w", err)
	}

	return nil
}
