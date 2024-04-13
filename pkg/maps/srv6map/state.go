// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

import (
	"os"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	stateMapName4 = "cilium_srv6_state_v4"
	stateMapName6 = "cilium_srv6_state_v6"
)

// We can delete this in v1.18
func cleanupStateMap() {
	os.Remove(bpf.MapPath(stateMapName4))
	os.Remove(bpf.MapPath(stateMapName6))
}
