// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	ctrlRuntime "sigs.k8s.io/controller-runtime"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// Cell manages the CiliumEnvoyConfig related controllers.
var Cell = cell.Module(
	"ciliumenvoyconfig",
	"Manages the CiliumEnvoyConfig controllers",

	cell.Config(l7LoadBalancerConfig{
		LoadBalancerL7Ports:     []string{},
		LoadBalancerL7Algorithm: "round_robin",
	}),
	cell.Invoke(registerL7LoadBalancingController),
)

type l7LoadBalancerConfig struct {
	LoadBalancerL7Algorithm string
	LoadBalancerL7Ports     []string
}

func (r l7LoadBalancerConfig) Flags(flags *pflag.FlagSet) {
	flags.String("loadbalancer-l7-algorithm", r.LoadBalancerL7Algorithm, "Default LB algorithm for services that do not specify related annotation")
	flags.StringSlice("loadbalancer-l7-ports", r.LoadBalancerL7Ports, "List of service ports that will be automatically redirected to backend.")
}

type l7LoadbalancerParams struct {
	cell.In

	Logger             logrus.FieldLogger
	CtrlRuntimeManager ctrlRuntime.Manager
	Config             l7LoadBalancerConfig
}

func registerL7LoadBalancingController(params l7LoadbalancerParams) error {
	if operatorOption.Config.LoadBalancerL7 != "envoy" {
		return nil
	}

	params.Logger.Info("Register Envoy load balancer reconciler")

	reconciler := newCiliumEnvoyConfigReconciler(
		params.CtrlRuntimeManager.GetClient(),
		params.Logger,
		params.Config.LoadBalancerL7Algorithm,
		params.Config.LoadBalancerL7Ports,
		10,
		operatorOption.Config.ProxyIdleTimeoutSeconds,
	)

	if err := reconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
		return fmt.Errorf("failed to setup Envoy load balancer reconciler: %w", err)
	}

	return nil
}
