// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/node"
)

func (s *LoaderTestSuite) SetUpTest(c *C) {
	node.InitDefaultPrefix("")
	node.SetInternalIPv4Router(templateIPv4[:])
	node.SetIPv4Loopback(templateIPv4[:])
}
