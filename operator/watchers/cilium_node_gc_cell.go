// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/controller"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/option"
)

// CiliumNodeGCCell periodically garbage collects stale CiliumNode custom
// resources that no longer have a corresponding Kubernetes Node object.
// When CiliumNode CRD support is disabled it performs a one-off deletion of
// all existing CiliumNode objects.
var CiliumNodeGCCell = cell.Module(
	"cilium-node-gc",
	"CiliumNode garbage collector",

	cell.Config(ciliumNodeGCDefaultConfig),
	cell.Invoke(registerCiliumNodeGC),
)

// CiliumNodeGCConfig holds the configuration for the CiliumNode GC cell.
type CiliumNodeGCConfig struct {
	NodesGCInterval time.Duration
}

var ciliumNodeGCDefaultConfig = CiliumNodeGCConfig{
	NodesGCInterval: 5 * time.Minute,
}

func (def CiliumNodeGCConfig) Flags(flags *pflag.FlagSet) {
	flags.Duration("nodes-gc-interval", def.NodesGCInterval, "GC interval for CiliumNodes")
}

type ciliumNodeGCParams struct {
	cell.In

	Logger                   *slog.Logger
	Lifecycle                cell.Lifecycle
	Clientset                k8sClient.Clientset
	CiliumNodes              resource.Resource[*cilium_v2.CiliumNode]
	WorkQueueMetricsProvider workqueue.MetricsProvider
	DaemonConfig             *option.DaemonConfig

	Cfg CiliumNodeGCConfig
}

func registerCiliumNodeGC(p ciliumNodeGCParams) {
	if !p.Clientset.IsEnabled() {
		return
	}
	if p.Cfg.NodesGCInterval == 0 {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	gc := &ciliumNodeGC{
		ctx:                      ctx,
		cancel:                   cancel,
		clientset:                p.Clientset,
		ciliumNodes:              p.CiliumNodes,
		interval:                 p.Cfg.NodesGCInterval,
		enableCiliumNodeCRD:      p.DaemonConfig.EnableCiliumNodeCRD,
		workqueueMetricsProvider: p.WorkQueueMetricsProvider,
		logger:                   p.Logger,
		ctrlMgr:                  controller.NewManager(),
	}
	p.Lifecycle.Append(cell.Hook{
		OnStart: gc.start,
		OnStop:  gc.stop,
	})
}

type ciliumNodeGC struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	clientset                k8sClient.Clientset
	ciliumNodes              resource.Resource[*cilium_v2.CiliumNode]
	interval                 time.Duration
	enableCiliumNodeCRD      bool
	workqueueMetricsProvider workqueue.MetricsProvider
	logger                   *slog.Logger
	ctrlMgr                  *controller.Manager
}

func (g *ciliumNodeGC) start(startCtx cell.HookContext) error {
	var candidateStore *ciliumNodeGCCandidate
	var shouldGCPred func(
		ctx context.Context,
		nodeName string,
		ciliumNodeStore resource.Store[*cilium_v2.CiliumNode],
		nodeGetter slimNodeGetter,
		interval time.Duration,
		candidateStore *ciliumNodeGCCandidate,
		scopedLog *slog.Logger,
	) (bool, error)

	interval := g.interval

	if !g.enableCiliumNodeCRD {
		g.logger.InfoContext(startCtx, "Running one-off GC of CiliumNode CRD when disabled")
		interval = 0
		shouldGCPred = shouldGCNodeCRDDisabled
	} else {
		nodesInit(&g.wg, g.clientset.Slim(), g.ctx.Done(), g.workqueueMetricsProvider)

		// Wait for the node store to be synced before starting the GC loop
		// so that shouldGCNode can reliably determine whether a node exists.
		select {
		case <-slimNodeStoreSynced:
		case <-g.ctx.Done():
			return nil
		}

		g.logger.InfoContext(startCtx, "Starting to garbage collect stale CiliumNode custom resources")
		candidateStore = newCiliumNodeGCCandidate()
		shouldGCPred = shouldGCNode
	}

	ciliumNodeStore, err := g.ciliumNodes.Store(g.ctx)
	if err != nil {
		return err
	}

	g.ctrlMgr.UpdateController("cilium-node-gc",
		controller.ControllerParams{
			Group:   controller.NewGroup("cilium-node-gc"),
			Context: g.ctx,
			DoFunc: func(ctx context.Context) error {
				return performCiliumNodeGC(
					ctx,
					g.clientset.CiliumV2().CiliumNodes(),
					ciliumNodeStore,
					nodeGetter{},
					interval,
					candidateStore,
					g.logger,
					shouldGCPred,
				)
			},
			RunInterval: interval,
		},
	)

	return nil
}

func (g *ciliumNodeGC) stop(_ cell.HookContext) error {
	g.cancel()
	g.ctrlMgr.RemoveControllerAndWait("cilium-node-gc")
	g.wg.Wait()
	return nil
}
