// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"loader",
	"Loader",

	cell.Config(DefaultConfig),
	cell.Provide(NewLoader),
)

var DefaultConfig = Config{
	DeriveMasqIPAddrFromDevice: "",
}

type Config struct {
	// DeriveMasqIPAddrFromDevice specifies which devices IP addr is used for BPF masquerade.
	// See commit d204d789746b1389cc2ba02fdd55b81a2f55b76e for original context. This can
	// be removed once https://github.com/cilium/cilium/issues/17158 is resolved.
	DeriveMasqIPAddrFromDevice string
}

func (def Config) Flags(flags *pflag.FlagSet) {
	const deriveFlag = "derive-masq-ip-addr-from-device"
	flags.String(
		deriveFlag, def.DeriveMasqIPAddrFromDevice,
		"Device name from which Cilium derives the IP addr for BPF masquerade")
	flags.MarkHidden(deriveFlag)
}
