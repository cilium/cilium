// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	loaderTypes "github.com/cilium/cilium/pkg/datapath/loader/types"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"loader",
	"Loader",

	cell.Config(DefaultConfig),
	cell.Provide(NewLoader),
)

// NewLoader returns a new loader.
func NewLoader(p Params) loaderTypes.Loader {
	return newLoader(p)
}

var DefaultConfig = Config{
	// By default the masquerading IP is the primary IP address of the device in
	// question.
	DeriveMasqIPAddrFromDevice: "",
}

type Config struct {
	// DeriveMasqIPAddrFromDevice specifies which device's IP addr is used for BPF masquerade.
	// This is a hidden option and by default not set. Only needed in very specific setups
	// with ECMP and multiple devices.
	// See commit d204d789746b1389cc2ba02fdd55b81a2f55b76e for original context.
	// This can be removed once https://github.com/cilium/cilium/issues/17158 is resolved.
	DeriveMasqIPAddrFromDevice string
}

func (def Config) Flags(flags *pflag.FlagSet) {
	const deriveFlag = "derive-masq-ip-addr-from-device"
	flags.String(
		deriveFlag, def.DeriveMasqIPAddrFromDevice,
		"Device name from which Cilium derives the IP addr for BPF masquerade")
	flags.MarkHidden(deriveFlag)
}
