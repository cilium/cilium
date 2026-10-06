// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"net/netip"

	"github.com/cilium/cilium/api/v1/models"
)

type IDHandler struct{}

func (n *IDHandler) GetNodeID(_ netip.Addr) (uint16, bool) {
	return 0, true
}

// NewIDHandler returns a fake node ID handler.
func NewIDHandler() *IDHandler {
	return &IDHandler{}
}

func (n *IDHandler) GetNodeIP(_ uint16) string {
	return ""
}

func (n *IDHandler) DumpNodeIDs() []*models.NodeID {
	return nil
}

func (n *IDHandler) RestoreNodeIDs() {
}
