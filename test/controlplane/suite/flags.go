// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package suite

import (
	"flag"

	"github.com/cilium/cilium/pkg/logging"
)

// Flags common to controlplane tests.
var (
	FlagUpdate = flag.Bool("update", false, "Update golden test files")
	FlagDebug  = flag.Bool("debug", false, "Enable debug logging")
)

func ParseFlags() {
	flag.Parse()
	if *FlagDebug {
		logging.SetLogLevelToDebug()
	}
	logging.InitializeDefaultLogger()
}
