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

	cell.Invoke(registerCECK8sManager),
	cell.ProvidePrivate(newEnvoyServiceBackendSyncer),
	cell.ProvidePrivate(newCECResourceParser),
)

type managerParams struct {
	cell.In

	Logger      logrus.FieldLogger
	Lifecycle   cell.Lifecycle
	JobRegistry job.Registry
	Scope       cell.Scope

	PolicyUpdater  *policy.Updater
	ServiceManager service.ServiceManager

	XdsServer      envoy.XDSServer
	BackendSyncer  *envoyServiceBackendSyncer
	ResourceParser *cecResourceParser

	CECResources   resource.Resource[*ciliumv2.CiliumEnvoyConfig]
	CCECResources  resource.Resource[*ciliumv2.CiliumClusterwideEnvoyConfig]
	LocalNodeStore *node.LocalNodeStore
}

func registerCECK8sManager(params managerParams) {
	if !option.Config.EnableL7Proxy || !option.Config.EnableEnvoyConfig {
		return
	}

	mgr := newCiliumEnvoyConfigManager(params.Logger, params.PolicyUpdater, params.ServiceManager, params.XdsServer, params.BackendSyncer, params.ResourceParser)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			localNode, err := params.LocalNodeStore.Get(ctx)
			if err != nil {
				return fmt.Errorf("failed to get LocalNodeStore: %w", err)
			}

			mgr.localNodeLabels = localNode.Labels

			params.Logger.
				WithField(logfields.Labels, mgr.localNodeLabels).
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

	jobGroup.Add(job.Observer("cec-resource-events", mgr.handleCECEvent, params.CECResources))
	jobGroup.Add(job.Observer("ccec-resource-events", mgr.handleCCECEvent, params.CCECResources))

	// Observing local node events for changed labels
	// Note: LocalNodeStore (in comparison to `resource.Resource`) doesn't provide a retry mechanism
	jobGroup.Add(job.Observer("local-node-events", mgr.handleLocalNodeEvent, params.LocalNodeStore))
}
