// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/maps/nodemap"
)

type fakeNodeMapV2 struct {
	ids map[string]nodemap.NodeValueV2
}

func NewFakeNodeMapV2() *fakeNodeMapV2 {
	return &fakeNodeMapV2{
		ids: map[string]nodemap.NodeValueV2{},
	}
}

func (f fakeNodeMapV2) Update(ip net.IP, nodeID uint16, SPI uint8) error {
	f.ids[ip.String()] = nodemap.NodeValueV2{
		NodeID: nodeID,
		SPI:    SPI,
	}
	return nil
}

func (f fakeNodeMapV2) Size() uint32 {
	return nodemap.DefaultMaxEntries
}

func (f fakeNodeMapV2) Delete(ip net.IP) error {
	delete(f.ids, ip.String())
	return nil
}

// This function is used only for tests.
func (f fakeNodeMapV2) Lookup(ip net.IP) (*nodemap.NodeValueV2, error) {
	if nodeValue, exists := f.ids[ip.String()]; exists {
		return &nodeValue, nil
	}
	return nil, fmt.Errorf("IP not found in node ID map")
}

func (f fakeNodeMapV2) IterateWithCallback(cb nodemap.NodeIterateCallbackV2) error {
	return nil
}
