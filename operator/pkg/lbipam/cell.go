// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"lbipam",
	"LB-IPAM",
	// Provide LBIPAM so instances of it can be used while testing
	cell.Provide(
		newLBIPAM,
		func(c lbipamConfig) Config { return c },
	),
	// Invoke an empty function which takes an LBIPAM to force its construction.
	cell.Invoke(func(*LBIPAM) {}),
	// Register configuration flags
	cell.Config(lbipamConfig{}),
)

type LBIPAMParams struct {
	cell.In

	Logger logrus.FieldLogger

	LC          cell.Lifecycle
	Shutdowner  hive.Shutdowner
	JobRegistry job.Registry

	Clientset    k8sClient.Clientset
	PoolResource resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool]
	SvcResource  resource.Resource[*slim_core_v1.Service]

	DaemonConfig *option.DaemonConfig
}

type lbipamConfig struct {
}

func (lc lbipamConfig) Flags(flags *pflag.FlagSet) {
}

func (lc lbipamConfig) IsEnabled() bool {
	return true
}

type Config interface {
	IsEnabled() bool
}
