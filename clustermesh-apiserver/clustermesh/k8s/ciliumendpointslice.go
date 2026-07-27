// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"github.com/spf13/pflag"
)

type CiliumEndpointSliceConfig struct {
	EnableCiliumEndpointSlice bool
}

func (def CiliumEndpointSliceConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-cilium-endpoint-slice", def.EnableCiliumEndpointSlice, "Enables the CiliumEndpointSlice feature")
}

var DefaultCiliumEndpointSliceConfig = CiliumEndpointSliceConfig{
	EnableCiliumEndpointSlice: false,
}
