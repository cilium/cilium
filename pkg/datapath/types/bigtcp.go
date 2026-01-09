// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/spf13/pflag"
)

const (
	EnableIPv4BIGTCPFlag   = "enable-ipv4-big-tcp"
	EnableIPv6BIGTCPFlag   = "enable-ipv6-big-tcp"
	EnableTunnelBIGTCPFlag = "enable-tunnel-big-tcp"
)

// BigTCPUserConfig are the configuration flags that the user can modify.
type BigTCPUserConfig struct {
	// EnableIPv6BIGTCP enables IPv6 BIG TCP (larger GSO/GRO limits) for the node including pods.
	EnableIPv6BIGTCP bool

	// EnableIPv4BIGTCP enables IPv4 BIG TCP (larger GSO/GRO limits) for the node including pods.
	EnableIPv4BIGTCP bool

	// EnableTunnelBIGTCP enables BIG TCP (larger GSO/GRO limits) in tunneling mode for VXLAN and GENEVE tunnels.
	EnableTunnelBIGTCP bool
}

func (def BigTCPUserConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableIPv4BIGTCPFlag, def.EnableIPv4BIGTCP, "Enable IPv4 BIG TCP option which increases device's maximum GRO/GSO limits for IPv4")
	flags.Bool(EnableIPv6BIGTCPFlag, def.EnableIPv6BIGTCP, "Enable IPv6 BIG TCP option which increases device's maximum GRO/GSO limits for IPv6")
	flags.Bool(EnableTunnelBIGTCPFlag, def.EnableTunnelBIGTCP, "Enable BIG TCP in tunneling mode and increase maximum GRO/GSO limits for VXLAN/GENEVE tunnels")
}

func (def BigTCPUserConfig) IsIPv4Enabled() bool {
	return def.EnableIPv4BIGTCP
}

func (def BigTCPUserConfig) IsIPv6Enabled() bool {
	return def.EnableIPv6BIGTCP
}

func (def BigTCPUserConfig) IsTunnelEnabled() bool {
	return def.EnableTunnelBIGTCP
}

type BigTCPConfig interface {
	IsIPv4Enabled() bool
	IsIPv6Enabled() bool
	IsTunnelEnabled() bool
}

type BigTCPConfiguration interface {
	GetGROIPv6MaxSize() int
	GetGSOIPv6MaxSize() int
	GetGROIPv4MaxSize() int
	GetGSOIPv4MaxSize() int
}
