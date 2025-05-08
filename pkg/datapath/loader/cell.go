// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

var Cell = cell.Module(
	"loader",
	"Loader",

	cell.Provide(NewLoader),
	cell.Provide(NewCompilationLock),
	cell.Config(&Config{
		ErrorOnUnusedMaps: false,
	}),
)

type Config struct {
	// We have logic to remove unused maps from collection specs before they are loaded.
	// This is an optimization to avoid using memory for maps which are not used.
	// Normally this causes a warning, but during CI we want to throw an error
	// to make visible that something is going wrong.
	ErrorOnUnusedMaps bool
}

func (c *Config) Flags(flags *pflag.FlagSet) {
	flags.BoolVar(&c.ErrorOnUnusedMaps, "error-on-unused-maps", false, "Throw an error if after loading a collection contains maps that are not used")
	_ = flags.MarkHidden("error-on-unused-maps")
}

// NewLoader returns a new loader.
func NewLoader(p Params) datapath.Loader {
	return newLoader(p)
}
