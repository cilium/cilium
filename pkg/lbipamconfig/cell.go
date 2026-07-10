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
		EnableLBIPAM:         true,
		DefaultLBServiceIPAM: DefaultLBClassLBIPAM,
	}),
)

type lbipamConfig struct {
	// EnableIPAM indicates if LB-IPAM is enabled
	EnableLBIPAM bool

	// DefaultLBServiceIPAM indicate the default LoadBalancer Service IPAM
	DefaultLBServiceIPAM string
}

func (lc lbipamConfig) Flags(flags *pflag.FlagSet) {
	flags.BoolVar(&lc.EnableLBIPAM, "enable-lb-ipam", lc.EnableLBIPAM, "Enable LB IPAM")

	flags.StringVar(&lc.DefaultLBServiceIPAM, "default-lb-service-ipam", lc.DefaultLBServiceIPAM,
		"Indicates the default LoadBalancer Service IPAM when no LoadBalancer class is set."+
			"Applicable values: lbipam, nodeipam, none")
}

func (lc lbipamConfig) IsEnabled() bool {
	return lc.EnableLBIPAM
}

func (lc lbipamConfig) GetDefaultLBServiceIPAM() string {
	return lc.DefaultLBServiceIPAM
}

type Config interface {
	IsEnabled() bool
	GetDefaultLBServiceIPAM() string
}

const (
	DefaultLBClassLBIPAM   = "lbipam"
	DefaultLBClassNodeIPAM = "nodeipam"
)
