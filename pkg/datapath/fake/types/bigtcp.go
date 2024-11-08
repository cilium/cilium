// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

// BigTCPUserConfig are the configuration flags that the user can modify.
type BigTCPUserConfig struct {
	// EnableIPv6BIGTCP enables IPv6 BIG TCP (larger GSO/GRO limits) for the node including pods.
	EnableIPv6BIGTCP bool

	// EnableIPv4BIGTCP enables IPv4 BIG TCP (larger GSO/GRO limits) for the node including pods.
	EnableIPv4BIGTCP bool
}

func (def BigTCPUserConfig) IsIPv4Enabled() bool {
	return def.EnableIPv4BIGTCP
}

func (def BigTCPUserConfig) IsIPv6Enabled() bool {
	return def.EnableIPv6BIGTCP
}
