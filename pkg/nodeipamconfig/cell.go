// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodeipamconfig

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/annotation"
)

var Cell = cell.Module(
	"nodeipamconfig",
	"Node-IPAM-Config",

	cell.Provide(func(r nodeIpamConfig) NodeIPAMConfig { return r }),
	cell.Config(nodeIpamConfig{}),
)

type nodeIpamConfig struct {
	EnableNodeIPAM bool
}

func (r nodeIpamConfig) IsEnabled() bool {
	return r.EnableNodeIPAM
}

type NodeIPAMConfig interface {
	IsEnabled() bool
}

func (r nodeIpamConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-node-ipam", r.EnableNodeIPAM, "Enable Node IPAM")
}

const (
	NodeSvcLBClass                 = annotation.Prefix + "/node"
	NodeSvcLBMatchLabelsAnnotation = annotation.Prefix + ".nodeipam" + "/match-node-labels"
)
