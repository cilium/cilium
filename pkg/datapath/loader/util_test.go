// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"testing"

	"github.com/cilium/cilium/pkg/node"
)

func setupLocalNodeStore(tb testing.TB) {
	node.SetTestLocalNodeStore()
	node.InitDefaultPrefix("")
	node.SetInternalIPv4Router(templateIPv4[:])
	node.SetIPv4Loopback(templateIPv4[:])
	tb.Cleanup(node.UnsetTestLocalNodeStore)
}
