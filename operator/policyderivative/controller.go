// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policyderivative

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/hive/cell"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

type params struct {
	cell.In

	Lifecycle            cell.Lifecycle
	SharedCfg            SharedConfig
	Clientset            k8sClient.Clientset
	Logger               *slog.Logger
	CfgClusterMeshPolicy cmtypes.PolicyConfig
}

func registerWatchers(p params) {
	// Check if watchers should be enabled
	if !p.SharedCfg.K8sEnabled {
		p.Logger.Info("Policy derivative watchers disabled due to kubernetes support not enabled")
		return
	}

	if !p.SharedCfg.EnableCiliumNetworkPolicy && !p.SharedCfg.EnableCiliumClusterwideNetworkPolicy {
		p.Logger.Info("Policy derivative watchers disabled as both CNP and CCNP are disabled")
		return
	}

	clusterNamePolicy := cmtypes.LocalClusterNameForPolicies(p.CfgClusterMeshPolicy, p.SharedCfg.ClusterName)

	c := &policyDerivativeController{
		clientset:      p.Clientset,
		logger:         p.Logger,
		updateInterval: 5 * time.Minute,
		clusterName:    clusterNamePolicy,
		enableCNP:      p.SharedCfg.EnableCiliumNetworkPolicy,
		enableCCNP:     p.SharedCfg.EnableCiliumClusterwideNetworkPolicy,
	}

	p.Lifecycle.Append(cell.Hook{
		OnStart: c.onStart,
		OnStop:  c.onStop,
	})
}

type policyDerivativeController struct {
	clientset      k8sClient.Clientset
	logger         *slog.Logger
	updateInterval time.Duration
	clusterName    string
	enableCNP      bool
	enableCCNP     bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (c *policyDerivativeController) onStart(ctx cell.HookContext) error {
	c.ctx, c.cancel = context.WithCancel(context.Background())

	if c.enableCNP {
		c.wg.Go(func() {
			c.startCNPWatcher()
		})
	}

	if c.enableCCNP {
		c.wg.Go(func() {
			c.startCCNPWatcher()
		})
	}

	return nil
}

func (c *policyDerivativeController) onStop(_ cell.HookContext) error {
	c.cancel()
	c.wg.Wait()
	return nil
}
