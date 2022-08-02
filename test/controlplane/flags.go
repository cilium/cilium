// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controlplane

import (
	"flag"
)

// Flags
var (
	flagUpdate = flag.Bool("update", false, "Update golden test files")
	flagDebug  = flag.Bool("debug", false, "Enable debug logging")
)
