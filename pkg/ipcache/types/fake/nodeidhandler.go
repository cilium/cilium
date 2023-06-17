// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import "net"

type FakeNodeIDHandler struct{}

func (m *FakeNodeIDHandler) GetNodeID(_ net.IP) (nodeID uint16, exists bool) {
	return 0, true
}

func (m *FakeNodeIDHandler) AllocateNodeID(_ net.IP) uint16 {
	return 0
}

func (m *FakeNodeIDHandler) GetNodeIP(_ uint16) string {
	return ""
}
