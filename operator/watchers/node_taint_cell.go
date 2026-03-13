// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/defaults"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// NodeTaintSyncCell manages node taints and conditions based on Cilium pod
// readiness. It removes the agent-not-ready taint once Cilium is running on
// a node, and optionally sets it when Cilium is scheduled but not yet ready.
var NodeTaintSyncCell = cell.Module(
	"node-taint-sync",
	"Manages node taints and conditions based on Cilium pod readiness",

	cell.Config(nodeTaintSyncDefaultConfig),
	cell.Invoke(registerNodeTaintSync),
)

// NodeTaintSyncConfig holds the configuration owned by the node taint sync cell.
// CiliumK8sNamespace and CiliumPodLabels are shared with other cells and
// therefore remain in OperatorConfig.
type NodeTaintSyncConfig struct {
	TaintSyncWorkers       int
	RemoveCiliumNodeTaints bool
	SetCiliumNodeTaints    bool
	SetCiliumIsUpCondition bool
}

var nodeTaintSyncDefaultConfig = NodeTaintSyncConfig{
	TaintSyncWorkers:       10,
	RemoveCiliumNodeTaints: true,
	SetCiliumNodeTaints:    false,
	SetCiliumIsUpCondition: true,
}

func (def NodeTaintSyncConfig) Flags(flags *pflag.FlagSet) {
	flags.Int("taint-sync-workers", def.TaintSyncWorkers,
		"Number of workers used to synchronize node taints and conditions")
	flags.Bool("remove-cilium-node-taints", def.RemoveCiliumNodeTaints,
		fmt.Sprintf("Remove node taint %q from Kubernetes nodes once Cilium is up and running", defaults.AgentNotReadyNodeTaint))
	flags.Bool("set-cilium-node-taints", def.SetCiliumNodeTaints,
		fmt.Sprintf("Set node taint %q on Kubernetes nodes if Cilium is scheduled but not up and running", defaults.AgentNotReadyNodeTaint))
	flags.Bool("set-cilium-is-up-condition", def.SetCiliumIsUpCondition,
		"Set CiliumIsUp Node condition to mark a Kubernetes Node that a Cilium pod is up and running in that node")
}

type nodeTaintSyncParams struct {
	cell.In

	Logger      *slog.Logger
	Lifecycle   cell.Lifecycle
	Clientset   k8sClient.Clientset
	OperatorCfg *operatorOption.OperatorConfig

	Cfg NodeTaintSyncConfig
}

func registerNodeTaintSync(p nodeTaintSyncParams) {
	if !p.Clientset.IsEnabled() {
		return
	}
	if !p.Cfg.RemoveCiliumNodeTaints && !p.Cfg.SetCiliumIsUpCondition {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(hookCtx cell.HookContext) error {
			p.Logger.InfoContext(hookCtx,
				"Managing Cilium Node Taints or Setting Cilium Is Up Condition for Kubernetes Nodes",
				logfields.K8sNamespace, p.OperatorCfg.CiliumK8sNamespace,
				logfields.LabelSelectorFlagOption, p.OperatorCfg.CiliumPodLabels,
				logfields.RemoveCiliumNodeTaintsFlagOption, p.Cfg.RemoveCiliumNodeTaints,
				logfields.SetCiliumNodeTaintsFlagOption, p.Cfg.SetCiliumNodeTaints,
				logfields.SetCiliumIsUpConditionFlagOption, p.Cfg.SetCiliumIsUpCondition,
			)
			HandleNodeTolerationAndTaints(&wg, p.Clientset, ctx.Done(), p.Logger, p.Cfg,
				p.OperatorCfg.CiliumK8sNamespace, p.OperatorCfg.CiliumPodLabels)
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			cancel()
			wg.Wait()
			return nil
		},
	})
}
