// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"runtime/pprof"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/service"
)

// Cell provides support for the CRD CiliumEnvoyConfig that backs Ingress, Gateway API
// and L7 loadbalancing.
var Cell = cell.Module(
	"ciliumenvoyconfig",
	"CiliumEnvoyConfig",

	cell.Invoke(registerCECK8sWatcher),
	cell.ProvidePrivate(newEnvoyServiceBackendSyncer),
	cell.ProvidePrivate(newCECResourceParser),
)

type watchParams struct {
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

	CECResources  resource.Resource[*ciliumv2.CiliumEnvoyConfig]
	CCECResources resource.Resource[*ciliumv2.CiliumClusterwideEnvoyConfig]
}

func registerCECK8sWatcher(params watchParams) {
	if !option.Config.EnableL7Proxy || !option.Config.EnableEnvoyConfig {
		return
	}

	jobGroup := params.JobRegistry.NewGroup(
		params.Scope,
		job.WithLogger(params.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "ciliumenvoyconfig")),
	)
	params.Lifecycle.Append(jobGroup)

	cecWatcher := newCiliumEnvoyConfigWatcher(params.Logger, params.PolicyUpdater, params.ServiceManager, params.XdsServer, params.BackendSyncer, params.ResourceParser)

	jobGroup.Add(job.Observer("cec-resource-events", cecWatcher.handleCECEvent, params.CECResources))
	jobGroup.Add(job.Observer("ccec-resource-events", cecWatcher.handleCCECEvent, params.CCECResources))
}
