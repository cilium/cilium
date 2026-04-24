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

	"github.com/cilium/cilium/operator/pkg/ciliumpod"
	"github.com/cilium/cilium/pkg/defaults"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
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
	AgentConfig *option.DaemonConfig
	PodCfg      ciliumpod.Config

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
	s := &nodeTaintSync{
		ctx:          ctx,
		cancel:       cancel,
		clientset:    p.Clientset,
		ciliumPodNS:  p.PodCfg.ResolveNamespace(p.AgentConfig.K8sNamespace),
		ciliumLabels: p.PodCfg.Labels,
		cfg:          p.Cfg,
		logger:       p.Logger,
	}
	p.Lifecycle.Append(cell.Hook{
		OnStart: s.start,
		OnStop:  s.stop,
	})
}

type nodeTaintSync struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	clientset    k8sClient.Clientset
	ciliumPodNS  string
	ciliumLabels string
	cfg          NodeTaintSyncConfig
	logger       *slog.Logger
}

func (s *nodeTaintSync) start(ctx cell.HookContext) error {
	s.logger.InfoContext(ctx,
		"Managing Cilium Node Taints or Setting Cilium Is Up Condition for Kubernetes Nodes",
		logfields.K8sNamespace, s.ciliumPodNS,
		logfields.LabelSelectorFlagOption, s.ciliumLabels,
		logfields.RemoveCiliumNodeTaintsFlagOption, s.cfg.RemoveCiliumNodeTaints,
		logfields.SetCiliumNodeTaintsFlagOption, s.cfg.SetCiliumNodeTaints,
		logfields.SetCiliumIsUpConditionFlagOption, s.cfg.SetCiliumIsUpCondition,
	)
	HandleNodeTolerationAndTaints(&s.wg, s.clientset, s.ctx.Done(), s.logger, s.cfg,
		s.ciliumPodNS, s.ciliumLabels)
	return nil
}

func (s *nodeTaintSync) stop(_ cell.HookContext) error {
	s.cancel()
	s.wg.Wait()
	return nil
}
