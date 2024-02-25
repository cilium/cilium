// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"fmt"
	"runtime/pprof"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/service"
)

// Cell provides support for the CRD CiliumEnvoyConfig that backs Ingress, Gateway API
// and L7 loadbalancing.
var Cell = cell.Module(
	"ciliumenvoyconfig",
	"CiliumEnvoyConfig",

	cell.Invoke(registerCECK8sReconciler),
	cell.ProvidePrivate(newCECManager),
	cell.ProvidePrivate(newCECResourceParser),
	cell.ProvidePrivate(newEnvoyServiceBackendSyncer),
)

type reconcilerParams struct {
	cell.In

	Logger      logrus.FieldLogger
	Lifecycle   cell.Lifecycle
	JobRegistry job.Registry
	Scope       cell.Scope

	Manager ciliumEnvoyConfigManager

	CECResources   resource.Resource[*ciliumv2.CiliumEnvoyConfig]
	CCECResources  resource.Resource[*ciliumv2.CiliumClusterwideEnvoyConfig]
	LocalNodeStore *node.LocalNodeStore
}

func registerCECK8sReconciler(params reconcilerParams) {
	if !option.Config.EnableL7Proxy || !option.Config.EnableEnvoyConfig {
		return
	}

	reconciler := newCiliumEnvoyConfigReconciler(params.Logger, params.Manager)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			localNode, err := params.LocalNodeStore.Get(ctx)
			if err != nil {
				return fmt.Errorf("failed to get LocalNodeStore: %w", err)
			}

			reconciler.localNodeLabels = localNode.Labels

			params.Logger.
				WithField(logfields.Labels, reconciler.localNodeLabels).
				Debug("Retrieved initial labels from local Node")

			return nil
		},
	})

	jobGroup := params.JobRegistry.NewGroup(
		params.Scope,
		job.WithLogger(params.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "ciliumenvoyconfig")),
	)
	params.Lifecycle.Append(jobGroup)

	jobGroup.Add(job.Observer("cec-resource-events", reconciler.handleCECEvent, params.CECResources))
	jobGroup.Add(job.Observer("ccec-resource-events", reconciler.handleCCECEvent, params.CCECResources))

	// Observing local node events for changed labels
	// Note: LocalNodeStore (in comparison to `resource.Resource`) doesn't provide a retry mechanism
	jobGroup.Add(job.Observer("local-node-events", reconciler.handleLocalNodeEvent, params.LocalNodeStore))
}

type managerParams struct {
	cell.In

	Logger logrus.FieldLogger

	PolicyUpdater  *policy.Updater
	ServiceManager service.ServiceManager

	XdsServer      envoy.XDSServer
	BackendSyncer  *envoyServiceBackendSyncer
	ResourceParser *cecResourceParser
}

func newCECManager(params managerParams) ciliumEnvoyConfigManager {
	return newCiliumEnvoyConfigManager(params.Logger, params.PolicyUpdater, params.ServiceManager, params.XdsServer, params.BackendSyncer, params.ResourceParser)
}
