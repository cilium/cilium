// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodesgc

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

// Cell handles the garbage collection of stale node entries from the kvstore.
var Cell = cell.Module(
	"kvstore-nodes-gc",
	"GC of stale KVStore node entries",

	cell.Config(Config{Enable: true}),
	cell.ProvidePrivate(newGC),
	cell.Invoke(func(*gc) {}),
)

type Config struct {
	Enable bool `mapstructure:"synchronize-k8s-nodes"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("synchronize-k8s-nodes", def.Enable, "Perform GC of stale node entries from the KVStore")
}
