// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package safenetlink

type Option func(*config)

type config struct {
	nlFamilies   []int
	enableVFInfo bool
}

// WithVFInfoCollections enables Virtual Function info collection in RTM_GETLINK
func WithVFInfoCollections() Option {
	return func(c *config) { c.enableVFInfo = true }
}

// WithFamily specifies a netlink family for the handle
func WithFamily(family int) Option {
	return func(c *config) { c.nlFamilies = append(c.nlFamilies, family) }
}
