// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"net"

	"github.com/cilium/cilium/pkg/maps/nodemap"
)

type fakeNodeMap struct {
}

var _ nodemap.Map = &fakeNodeMap{}

func NewFakeNodeMap() *fakeNodeMap {
	return &fakeNodeMap{}
}

func (f fakeNodeMap) Update(ip net.IP, nodeID uint16) error {
	return nil
}

func (f fakeNodeMap) Delete(ip net.IP) error {
	return nil
}

func (f fakeNodeMap) IterateWithCallback(cb nodemap.NodeIterateCallback) error {
	return nil
}
