// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"context"
	"net"
	"net/netip"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/stream"
	"github.com/cilium/cilium/pkg/time"
)

type desiredState struct {
	installRules bool

	devices       sets.Set[string]
	localNodeInfo localNodeInfo
	proxies       sets.Set[proxyInfo]
	ipv4Set       sets.Set[netip.Addr]
	ipv6Set       sets.Set[netip.Addr]
	noTrackPods   sets.Set[noTrackPodInfo]
}

type localNodeInfo struct {
	internalIPv4  net.IP
	internalIPv6  net.IP
	ipv4AllocCIDR string
	ipv6AllocCIDR string
}

func (lni localNodeInfo) equal(other localNodeInfo) bool {
	if !lni.internalIPv4.Equal(other.internalIPv4) ||
		!lni.internalIPv6.Equal(other.internalIPv6) ||
		lni.ipv4AllocCIDR != other.ipv4AllocCIDR ||
		lni.ipv6AllocCIDR != other.ipv6AllocCIDR {
		return false
	}
	return true
}

func toLocalNodeInfo(n node.LocalNode) localNodeInfo {
	var v4AllocCIDR, v6AllocCIDR string

	if n.IPv4AllocCIDR != nil {
		v4AllocCIDR = n.IPv4AllocCIDR.String()
	}
	if n.IPv6AllocCIDR != nil {
		v6AllocCIDR = n.IPv6AllocCIDR.String()
	}

	return localNodeInfo{
		internalIPv4:  n.GetCiliumInternalIP(false),
		internalIPv6:  n.GetCiliumInternalIP(true),
		ipv4AllocCIDR: v4AllocCIDR,
		ipv6AllocCIDR: v6AllocCIDR,
	}
}

type proxyInfo struct {
	name        string
	port        uint16
	isIngress   bool
	isLocalOnly bool
}

type noTrackPodInfo struct {
	ip   netip.Addr
	port uint16
}

func reconciliationLoop(
	ctx context.Context,
	log logrus.FieldLogger,
	health cell.HealthReporter,
	installIptRules bool,
	dependents *dependents,
	updateRules func(state desiredState, firstInit bool) error,
) error {
	// The minimum interval between reconciliation attempts
	const minReconciliationInterval = time.Second / 5

	state := desiredState{
		installRules: installIptRules,
		proxies:      sets.New[proxyInfo](),
		ipv4Set:      sets.New[netip.Addr](),
		ipv6Set:      sets.New[netip.Addr](),
		noTrackPods:  sets.New[noTrackPodInfo](),
	}

	localNodeEvents := stream.ToChannel(ctx, dependents.localNodeStore)
	state.localNodeInfo = toLocalNodeInfo(<-localNodeEvents)

	devices, devicesWatch := tables.SelectedDevices(dependents.devices, dependents.db.ReadTxn())
	state.devices = sets.New(tables.DeviceNames(devices)...)

	// Use a ticker to limit how often the desired state is reconciled to avoid doing
	// lots of operations when e.g. ipset updates.
	ticker := time.NewTicker(minReconciliationInterval)
	defer ticker.Stop()

	// stateChanged is true when the desired state has changed or when reconciling it
	// has failed. It's set to false when reconciling succeeds.
	stateChanged := true

	firstInit := true

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-devicesWatch:
			devices, devicesWatch = tables.SelectedDevices(dependents.devices, dependents.db.ReadTxn())
			newDevices := sets.New(tables.DeviceNames(devices)...)
			if newDevices.Equal(state.devices) {
				continue
			}
			state.devices = newDevices
			stateChanged = true
		case localNode, ok := <-localNodeEvents:
			if !ok {
				return nil
			}
			localNodeInfo := toLocalNodeInfo(localNode)
			if localNodeInfo.equal(state.localNodeInfo) {
				continue
			}
			state.localNodeInfo = localNodeInfo
			stateChanged = true
		case proxyInfo, ok := <-dependents.proxies:
			if !ok {
				return nil
			}
			if state.proxies.Has(proxyInfo) {
				continue
			}
			state.proxies.Insert(proxyInfo)
			stateChanged = true
		case ip, ok := <-dependents.addIPInSet:
			if !ok {
				return nil
			}
			if state.ipv6Set.Has(ip) || state.ipv4Set.Has(ip) {
				continue
			}
			if ip.Is6() {
				state.ipv6Set[ip] = sets.Empty{}
			} else {
				state.ipv4Set[ip] = sets.Empty{}
			}
			stateChanged = true
		case ip, ok := <-dependents.delIPFromSet:
			if !ok {
				return nil
			}
			if !state.ipv6Set.Has(ip) && !state.ipv4Set.Has(ip) {
				continue
			}
			if ip.Is6() {
				delete(state.ipv6Set, ip)
			} else {
				delete(state.ipv4Set, ip)
			}
			stateChanged = true
		case noTrackPod, ok := <-dependents.addNoTrackPod:
			if !ok {
				return nil
			}
			if state.noTrackPods.Has(noTrackPod) {
				continue
			}
			state.noTrackPods[noTrackPod] = sets.Empty{}
			stateChanged = true
		case noTrackPod, ok := <-dependents.delNoTrackPod:
			if !ok {
				return nil
			}
			if !state.noTrackPods.Has(noTrackPod) {
				continue
			}
			delete(state.noTrackPods, noTrackPod)
			stateChanged = true
		case <-ticker.C:
			if !stateChanged {
				continue
			}

			log.WithField("state", state).Info("updating rules to reconcile state")

			if err := updateRules(state, firstInit); err != nil {
				health.Degraded("iptables rules update failed", err)
				// Keep stateChanged=true to try again on the next tick.
			} else {
				health.OK("iptables rules update completed")
				firstInit = false
				stateChanged = false
			}
		}
	}
}
