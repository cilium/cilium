// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"

	"github.com/spf13/pflag"

	operatorK8s "github.com/cilium/cilium/operator/k8s"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
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
	LoadBalancerL7Ports     []string
	LoadBalancerL7Algorithm string
}

func (r l7LoadBalancerConfig) Flags(flags *pflag.FlagSet) {
	flags.StringSlice("loadbalancer-l7-ports", r.LoadBalancerL7Ports, "List of service ports that will be automatically redirected to backend.")
	flags.String("loadbalancer-l7-algorithm", r.LoadBalancerL7Algorithm, "Default LB algorithm for services that do not specify related annotation")
}

func registerL7LoadBalancingController(lc hive.Lifecycle, clientset k8sClient.Clientset, resources operatorK8s.Resources, config l7LoadBalancerConfig) error {
	if operatorOption.Config.LoadBalancerL7 != "envoy" {
		return nil
	}

	ctx, cancelCtx := context.WithCancel(context.Background())

	lc.Append(hive.Hook{
		OnStart: func(_ hive.HookContext) error {
			log.Info("Starting Envoy load balancer controller")
			StartCECController(ctx, clientset, resources.Services,
				config.LoadBalancerL7Ports,
				config.LoadBalancerL7Algorithm,
				operatorOption.Config.ProxyIdleTimeoutSeconds,
			)
			return nil
		},
		OnStop: func(hive.HookContext) error {
			cancelCtx()
			return nil
		},
	})

	return nil
}
