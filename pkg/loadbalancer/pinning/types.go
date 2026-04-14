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

type addService struct {
	ServiceId string
	ServiceIp netip.Addr
}
type deleteService struct {
	ServiceId string
	ServiceIp netip.Addr
}
type syncService struct{}
type addNode struct {
	NodeId string
	NodeIp netip.Addr
}
type deleteNode struct {
	NodeId string
	NodeIp netip.Addr
}
type syncNode struct{}

func (addService) isReconcileUpdate()    {}
func (deleteService) isReconcileUpdate() {}
func (syncService) isReconcileUpdate()   {}
func (addNode) isReconcileUpdate()       {}
func (deleteNode) isReconcileUpdate()    {}
func (syncNode) isReconcileUpdate()      {}

type servicesMap map[string]netip.Addr
type nodesMap map[string]netip.Addr

type pinningMap map[maps.LbPinning4Key]maps.LbPinning4Value

type LbPinMapUpdateEvent struct{}
