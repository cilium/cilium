// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/maps/nodemap"
)

type fakeNodeMap struct {
	ids map[string]uint16
}

var _ nodemap.Map = &fakeNodeMap{}

func NewFakeNodeMap() *fakeNodeMap {
	return &fakeNodeMap{
		ids: map[string]uint16{},
	}
}

func (f fakeNodeMap) Update(ip net.IP, nodeID uint16) error {
	f.ids[ip.String()] = nodeID
	return nil
}

func (f fakeNodeMap) Delete(ip net.IP) error {
	delete(f.ids, ip.String())
	return nil
}

// This function is used only for tests.
func (f fakeNodeMap) Lookup(ip net.IP) (uint16, error) {
	if nodeID, exists := f.ids[ip.String()]; exists {
		return nodeID, nil
	}
	return 0, fmt.Errorf("IP not found in node ID map")
}

func (f fakeNodeMap) IterateWithCallback(cb nodemap.NodeIterateCallback) error {
	return nil
}
