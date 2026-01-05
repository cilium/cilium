// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipamconfig

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"lbipamconfig",
	"LB-IPAM-Config",

	cell.Provide(
		func(c lbipamConfig) Config { return c },
	),

	// Register configuration flags
	cell.Config(lbipamConfig{
		EnableLBIPAM: true,
	}),
	cell.Config(SharedConfig{
		DefaultLBServiceIPAM: DefaultLBClassLBIPAM,
	}),
)

type lbipamConfig struct {
	EnableLBIPAM bool
}

func (lc lbipamConfig) Flags(flags *pflag.FlagSet) {
	flags.BoolVar(&lc.EnableLBIPAM, "enable-lb-ipam", lc.EnableLBIPAM, "Enable LB IPAM")
}

func (lc lbipamConfig) IsEnabled() bool {
	return lc.EnableLBIPAM
}

type Config interface {
	IsEnabled() bool
}

const (
	DefaultLBClassLBIPAM   = "lbipam"
	DefaultLBClassNodeIPAM = "nodeipam"
)

// SharedConfig contains the configuration that is shared between
// this module and others.
// It is a temporary solution meant to avoid polluting this module with a direct
// dependency on global operator configurations.
type SharedConfig struct {
	// DefaultLBServiceIPAM indicate the default LoadBalancer Service IPAM
	DefaultLBServiceIPAM string
}

func (sc SharedConfig) Flags(flags *pflag.FlagSet) {
	flags.StringVar(&sc.DefaultLBServiceIPAM, "default-lb-service-ipam", sc.DefaultLBServiceIPAM,
		"Indicates the default LoadBalancer Service IPAM when no LoadBalancer class is set."+
			"Applicable values: lbipam, nodeipam, none")
}
