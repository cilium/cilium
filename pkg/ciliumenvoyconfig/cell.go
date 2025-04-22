// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/service"
)

// Cell provides support for the CRD CiliumEnvoyConfig that backs Ingress, Gateway API
// and L7 loadbalancing.
var Cell = cell.Module(
	"ciliumenvoyconfig",
	"CiliumEnvoyConfig",

	cell.Config(CECConfig{}),
	cell.Invoke(registerCECK8sReconciler),
	cell.ProvidePrivate(newCECManager),
	cell.ProvidePrivate(newCECResourceParser),
	cell.ProvidePrivate(newEnvoyServiceBackendSyncer),
	cell.ProvidePrivate(newPortAllocator),

	experimentalCell,
)

type reconcilerParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	Health    cell.Health

	K8sResourceSynced *synced.Resources
	K8sAPIGroups      *synced.APIGroups

	Config    CECConfig
	ExpConfig loadbalancer.Config
	Manager   ciliumEnvoyConfigManager

	CECResources   resource.Resource[*ciliumv2.CiliumEnvoyConfig]
	CCECResources  resource.Resource[*ciliumv2.CiliumClusterwideEnvoyConfig]
	LocalNodeStore *node.LocalNodeStore

	EndpointResources resource.Resource[*k8s.Endpoints]
}

func registerCECK8sReconciler(params reconcilerParams) {
	if !option.Config.EnableL7Proxy || !option.Config.EnableEnvoyConfig || params.ExpConfig.EnableExperimentalLB {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	reconciler := newCiliumEnvoyConfigReconciler(params)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(startCtx cell.HookContext) error {
			localNode, err := params.LocalNodeStore.Get(startCtx)
			if err != nil {
				return fmt.Errorf("failed to get LocalNodeStore: %w", err)
			}

			reconciler.localNodeLabels = localNode.Labels

			params.Logger.Debug("Retrieved initial labels from local Node",
				logfields.Labels, reconciler.localNodeLabels,
			)

			return nil
		},
		OnStop: func(cell.HookContext) error {
			if cancel != nil {
				cancel()
			}
			return nil
		},
	})

	reconciler.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumEnvoyConfigV2, func() bool {
		return reconciler.cecSynced.Load()
	})
	reconciler.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumClusterwideEnvoyConfigV2, func() bool {
		return reconciler.ccecSynced.Load()
	})

	params.JobGroup.Add(job.Observer("cec-resource-events", reconciler.handleCECEvent, params.CECResources))
	params.JobGroup.Add(job.Observer("ccec-resource-events", reconciler.handleCCECEvent, params.CCECResources))

	// Observing local node events for changed labels
	// Note: LocalNodeStore (in comparison to `resource.Resource`) doesn't provide a retry mechanism
	params.JobGroup.Add(job.Observer("local-node-events", reconciler.handleLocalNodeEvent, params.LocalNodeStore))

	// Observing service events for headless services
	params.JobGroup.Add(job.Observer("headless-endpoint-events", reconciler.syncEndpoints, params.EndpointResources))

	// TimerJob periodically reconciles all existing configs.
	// This covers the cases were the reconciliation fails after changing the labels of a node.
	if params.Config.EnvoyConfigRetryInterval > 0 {
		params.JobGroup.Add(job.Timer("reconcile-existing-configs", reconciler.reconcileExistingConfigs, params.Config.EnvoyConfigRetryInterval))
	}
}

type CECMetrics interface {
	AddCEC(cec *ciliumv2.CiliumEnvoyConfigSpec)
	DelCEC(cec *ciliumv2.CiliumEnvoyConfigSpec)
	AddCCEC(spec *ciliumv2.CiliumEnvoyConfigSpec)
	DelCCEC(spec *ciliumv2.CiliumEnvoyConfigSpec)
}

type managerParams struct {
	cell.In

	Logger *slog.Logger

	Config      CECConfig
	EnvoyConfig envoy.ProxyConfig

	PolicyUpdater  *policy.Updater
	ServiceManager service.ServiceManager

	XdsServer      envoy.XDSServer
	BackendSyncer  *envoyServiceBackendSyncer
	ResourceParser *CECResourceParser

	Services  resource.Resource[*slim_corev1.Service]
	Endpoints resource.Resource[*k8s.Endpoints]

	MetricsManager CECMetrics
}

func newCECManager(params managerParams) ciliumEnvoyConfigManager {
	return newCiliumEnvoyConfigManager(params.Logger, params.PolicyUpdater, params.ServiceManager, params.XdsServer,
		params.BackendSyncer, params.ResourceParser, params.Config.EnvoyConfigTimeout, params.EnvoyConfig.ProxyMaxConcurrentRetries, params.Services, params.Endpoints, params.MetricsManager)
}

func newPortAllocator(proxy *proxy.Proxy) PortAllocator {
	return proxy
}
