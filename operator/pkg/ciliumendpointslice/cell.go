// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/cell"
)

const (
	// CESMaxCEPsInCES is the maximum number of cilium endpoints allowed in single
	// a CiliumEndpointSlice resource.
	CESMaxCEPsInCES = "ces-max-ciliumendpoints-per-ces"

	// CESSlicingMode instructs how CEPs are grouped in a CES.
	CESSlicingMode = "ces-slice-mode"

	// CESWriteQPSLimit is the rate limit per second for the CES work queue to
	// process  CES events that result in CES write (Create, Update, Delete)
	// requests to the kube-apiserver.
	CESWriteQPSLimit = "ces-write-qps-limit"

	// CESWriteQPSBurst is the burst rate per second used with CESWriteQPSLimit
	// for the CES work queue to process CES events that result in CES write
	// (Create, Update, Delete) requests to the kube-apiserver.
	CESWriteQPSBurst = "ces-write-qps-burst"
)

// Cell is a cell that implements a Cilium Endpoint Slice Controller.
// The controller subscribes to cilium endpoint and cilium endpoint slices
// events and reconciles the state of the cilium endpoint slices in the cluster.
var Cell = cell.Module(
	"k8s-ces-controller",
	"Cilium Endpoint Slice Controller",
	cell.Config(defaultConfig),
	cell.Invoke(registerController),
	cell.Metric(NewMetrics),
)

type Config struct {
	CESMaxCEPsInCES  int     `mapstructure:"ces-max-ciliumendpoints-per-ces"`
	CESSlicingMode   string  `mapstructure:"ces-slice-mode"`
	CESWriteQPSLimit float64 `mapstructure:"ces-write-qps-limit"`
	CESWriteQPSBurst int     `mapstructure:"ces-write-qps-burst"`
}

var defaultConfig = Config{
	CESMaxCEPsInCES:  100,
	CESSlicingMode:   "cesSliceModeIdentity",
	CESWriteQPSLimit: 10,
	CESWriteQPSBurst: 20,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Int(CESMaxCEPsInCES, def.CESMaxCEPsInCES, "Maximum number of CiliumEndpoints allowed in a CES")
	flags.String(CESSlicingMode, def.CESSlicingMode, "Slicing mode define how ceps are grouped into a CES")
	flags.Float64(CESWriteQPSLimit, def.CESWriteQPSLimit, "CES work queue rate limit")
	flags.Int(CESWriteQPSBurst, def.CESWriteQPSBurst, "CES work queue burst rate")
}

// SharedConfig contains the configuration that is shared between
// this module and others.
// It is a temporary solution meant to avoid polluting this module with a direct
// dependency on global operator and daemon configurations.
type SharedConfig struct {
	// EnableCiliumEndpointSlice enables the cilium endpoint slicing feature and the CES Controller.
	EnableCiliumEndpointSlice bool
}
