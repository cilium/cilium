// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

type Config struct {
	UserConfig
}

func (c *Config) GetGROIPv6MaxSize() int {
	return 65536
}

func (c *Config) GetGSOIPv6MaxSize() int {
	return 65536
}

func (c *Config) GetGROIPv4MaxSize() int {
	return 65536
}

func (c *Config) GetGSOIPv4MaxSize() int {
	return 65536
}

// UserConfig are the configuration flags that the user can modify.
type UserConfig struct {
	// EnableIPv6BIGTCP enables IPv6 BIG TCP (larger GSO/GRO limits) for the node including pods.
	EnableIPv6BIGTCP bool

	// EnableIPv4BIGTCP enables IPv4 BIG TCP (larger GSO/GRO limits) for the node including pods.
	EnableIPv4BIGTCP bool
}

func (def UserConfig) IsIPv4Enabled() bool {
	return def.EnableIPv4BIGTCP
}

func (def UserConfig) IsIPv6Enabled() bool {
	return def.EnableIPv6BIGTCP
}
