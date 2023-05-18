// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func (s *LoaderTestSuite) SetUpTest(c *C) {
	ctmap.InitMapInfo(option.CTMapEntriesGlobalTCPDefault, option.CTMapEntriesGlobalAnyDefault, true, true, true)
	node.InitDefaultPrefix("")
	node.SetInternalIPv4Router(templateIPv4[:])
	node.SetIPv4Loopback(templateIPv4[:])
}
