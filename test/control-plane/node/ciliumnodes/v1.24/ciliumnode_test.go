// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1_24

import (
	"testing"

	"github.com/cilium/cilium/pkg/option"
	controlplane "github.com/cilium/cilium/test/control-plane"
	node "github.com/cilium/cilium/test/control-plane/node/ciliumnodes"
)

func TestCiliumNodes1_24(t *testing.T) {
	tc := controlplane.NewGoldenTest(t, "cilium-nodes-control-plane", node.NewGoldenCiliumNodesValidator)
	tc.Run(t, "1.24", func(*option.DaemonConfig) {})
}
