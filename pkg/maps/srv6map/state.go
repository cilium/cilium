// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

import (
	"log/slog"
	"os"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	stateMapName4 = "cilium_srv6_state_v4"
	stateMapName6 = "cilium_srv6_state_v6"
)

// We can delete this in v1.18
func cleanupStateMap(logger *slog.Logger) {
	os.Remove(bpf.MapPath(logger, stateMapName4))
	os.Remove(bpf.MapPath(logger, stateMapName6))
}
