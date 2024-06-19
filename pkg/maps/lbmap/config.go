// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/option"
)

var configCell = cell.Group(
	cell.Config(defaultConfig),
	cell.Invoke(config.validate),
	cell.Provide(func(c config) Config { return c }),
)

// config defines the lbmap configuration flags. Unexported as we only want to
// expose the final computed values via [Config].
type config struct {
	// LBMapEntries is the maximum number of entries allowed in BPF lbmap.
	LBMapEntries int `mapstructure:"bpf-lb-map-max"`

	// LBServiceMapMaxEntries is the maximum number of entries allowed in BPF lbmap for services.
	// If unset [LBMapEntries is used].
	LBServiceMapMaxEntries int `mapstructure:"bpf-lb-service-map-max"`

	// LBBackendMapMaxEntries is the maximum number of entries allowed in BPF lbmap for service backends.
	// If unset [LBMapEntries is used].
	LBBackendMapMaxEntries int `mapstructure:"bpf-lb-service-backend-map-max"`

	// LBRevNatMaxEntries is the maximum number of entries allowed in BPF lbmap for reverse NAT.
	// If unset [LBMapEntries is used].
	LBRevNatMaxEntries int `mapstructure:"bpf-lb-rev-nat-map-max"`

	// LBAffinityMapMaxEntries is the maximum number of entries allowed in BPF lbmap for session affinities.
	// If unset [LBMapEntries is used].
	LBAffinityMapMaxEntries int `mapstructure:"bpf-lb-affinity-map-max"`

	// LBSourceRangeMapMaxEntries is the maximum number of entries allowed in BPF lbmap for source ranges.
	// If unset [LBMapEntries is used].
	LBSourceRangeMapMaxEntries int `mapstructure:"bpf-lb-source-range-map-max"`

	// LBMaglevMapMaxEntries is the maximum number of entries allowed in BPF lbmap for maglev.
	// If unset [LBMapEntries is used].
	LBMaglevMapMaxEntries int `mapstructure:"bpf-lb-maglev-map-max"`
}

func (c config) ServiceMapMaxEntries() int {
	return c.maxEntries(c.LBServiceMapMaxEntries)
}

func (c config) BackendMapMaxEntries() int {
	return c.maxEntries(c.LBBackendMapMaxEntries)
}

func (c config) RevNatMapMaxEntries() int {
	return c.maxEntries(c.LBRevNatMaxEntries)
}

func (c config) AffinityMapMaxEntries() int {
	return c.maxEntries(c.LBAffinityMapMaxEntries)
}

func (c config) SourceRangeMapMaxEntries() int {
	return c.maxEntries(c.LBSourceRangeMapMaxEntries)
}

func (c config) MaglevMapMaxEntries() int {
	return c.maxEntries(c.LBMaglevMapMaxEntries)
}

var defaultConfig = config{
	LBMapEntries:               DefaultMaxEntries,
	LBServiceMapMaxEntries:     0,
	LBBackendMapMaxEntries:     0,
	LBRevNatMaxEntries:         0,
	LBAffinityMapMaxEntries:    0,
	LBSourceRangeMapMaxEntries: 0,
	LBMaglevMapMaxEntries:      0,
}

func (def config) Flags(flags *pflag.FlagSet) {
	flags.Int(option.LBMapEntriesName, def.LBMapEntries,
		"Maximum number of entries in Cilium BPF lbmap")

	flags.Int(option.LBServiceMapMaxEntries, def.LBServiceMapMaxEntries,
		fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for services (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBServiceMapMaxEntries)

	flags.Int(option.LBBackendMapMaxEntries, def.LBBackendMapMaxEntries,
		fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for service backends (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBBackendMapMaxEntries)

	flags.Int(option.LBRevNatMapMaxEntries, def.LBRevNatMaxEntries,
		fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for reverse NAT (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBRevNatMapMaxEntries)

	flags.Int(option.LBAffinityMapMaxEntries, def.LBAffinityMapMaxEntries,
		fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for session affinities (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBAffinityMapMaxEntries)

	flags.Int(option.LBSourceRangeMapMaxEntries, def.LBSourceRangeMapMaxEntries,
		fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for source ranges (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBSourceRangeMapMaxEntries)

	flags.Int(option.LBMaglevMapMaxEntries, def.LBMaglevMapMaxEntries,
		fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for maglev (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBMaglevMapMaxEntries)
}

func (c config) maxEntries(opt int) int {
	if opt > 0 {
		return opt
	}
	return c.LBMapEntries
}

func (c config) validate() error {
	if c.LBMapEntries <= 0 {
		return fmt.Errorf("specified LBMap max entries %d must be a value greater than 0", c.LBMapEntries)
	}

	if c.LBServiceMapMaxEntries < 0 ||
		c.LBBackendMapMaxEntries < 0 ||
		c.LBRevNatMaxEntries < 0 ||
		c.LBAffinityMapMaxEntries < 0 ||
		c.LBSourceRangeMapMaxEntries < 0 ||
		c.LBMaglevMapMaxEntries < 0 {
		return fmt.Errorf("specified LB Service Map max entries must not be a negative value"+
			"(Service Map: %d, Service Backend: %d, Reverse NAT: %d, Session Affinity: %d, Source Range: %d, Maglev: %d)",
			c.LBServiceMapMaxEntries,
			c.LBBackendMapMaxEntries,
			c.LBRevNatMaxEntries,
			c.LBAffinityMapMaxEntries,
			c.LBSourceRangeMapMaxEntries,
			c.LBMaglevMapMaxEntries)
	}

	return nil
}
