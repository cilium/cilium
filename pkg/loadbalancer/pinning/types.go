// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pinning

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/loadbalancer/maps"
)

type reconcileUpdate interface {
	isReconcileUpdate()
}

type pinnedService struct {
	ServiceId string
	ServiceIp netip.Addr
	NodeId    string
}

type addService struct {
	pinnedService
}
type deleteService struct {
	pinnedService
}
type syncService struct{}

type nodeToPin struct {
	NodeName string
	NodeIp   netip.Addr
}

type addNode struct {
	nodeToPin
}

type deleteNode struct {
	nodeToPin
}

type syncNode struct{}

func (addService) isReconcileUpdate()    {}
func (deleteService) isReconcileUpdate() {}
func (syncService) isReconcileUpdate()   {}
func (addNode) isReconcileUpdate()       {}
func (deleteNode) isReconcileUpdate()    {}
func (syncNode) isReconcileUpdate()      {}

type servicesMap map[string]pinnedService
type nodesMap map[string]netip.Addr

type pinningMap map[maps.LbPinning4Key]maps.LbPinning4Value

type LbPinMapUpdateEvent struct{}
