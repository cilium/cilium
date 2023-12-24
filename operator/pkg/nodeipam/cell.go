// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodeipam

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	ctrlRuntime "sigs.k8s.io/controller-runtime"

	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

var Cell = cell.Module(
	"nodeipam",
	"Node-IPAM",

	cell.Config(nodeIpamConfig{}),
	cell.Invoke(registerNodeSvcLBReconciler),
)

type nodeipamCellParams struct {
	cell.In

	Logger             logrus.FieldLogger
	Clientset          k8sClient.Clientset
	CtrlRuntimeManager ctrlRuntime.Manager
	Config             nodeIpamConfig
}

type nodeIpamConfig struct {
	EnableNodeIPAM bool
}

func (r nodeIpamConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-node-ipam", r.EnableNodeIPAM, "Enable Node IPAM")
}

func registerNodeSvcLBReconciler(params nodeipamCellParams) error {
	if !params.Clientset.IsEnabled() || !params.Config.EnableNodeIPAM {
		return nil
	}

	if err := newNodeSvcLBReconciler(params.CtrlRuntimeManager, params.Logger).SetupWithManager(params.CtrlRuntimeManager); err != nil {
		return fmt.Errorf("Failed to register NodeSvcLBReconciler: %s", err)
	}

	return nil
}
