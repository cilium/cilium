// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bigtcp

import "github.com/spf13/pflag"

const (
	enableIPv4BIGTCPFlag = "enable-ipv4-big-tcp"
	enableIPv6BIGTCPFlag = "enable-ipv6-big-tcp"
)

// Features describes which features are enabled in the BigTCP datapath.
type Features interface {
	IsIPv4Enabled() bool
	IsIPv6Enabled() bool
}

// UserConfig are the configuration flags that the user can modify.
type UserConfig struct {
	// EnableIPv6BIGTCP enables IPv6 BIG TCP (larger GSO/GRO limits) for the node including pods.
	EnableIPv6BIGTCP bool

	// EnableIPv4BIGTCP enables IPv4 BIG TCP (larger GSO/GRO limits) for the node including pods.
	EnableIPv4BIGTCP bool
}

func (def UserConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(enableIPv4BIGTCPFlag, def.EnableIPv4BIGTCP, "Enable IPv4 BIG TCP option which increases device's maximum GRO/GSO limits for IPv4")
	flags.Bool(enableIPv6BIGTCPFlag, def.EnableIPv6BIGTCP, "Enable IPv6 BIG TCP option which increases device's maximum GRO/GSO limits for IPv6")
}

func (def UserConfig) IsIPv4Enabled() bool {
	return def.EnableIPv4BIGTCP
}

func (def UserConfig) IsIPv6Enabled() bool {
	return def.EnableIPv6BIGTCP
}
