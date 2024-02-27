// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"context"
	"net"
	"net/netip"

	"github.com/cilium/stream"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/time"
)

type desiredState struct {
	installRules bool

	devices       sets.Set[string]
	localNodeInfo localNodeInfo
	proxies       map[string]proxyInfo
	noTrackPods   sets.Set[noTrackPodInfo]
}

type localNodeInfo struct {
	internalIPv4  net.IP
	internalIPv6  net.IP
	ipv4AllocCIDR string
	ipv6AllocCIDR string
}

func (lni localNodeInfo) equal(other localNodeInfo) bool {
	if lni.internalIPv4.Equal(other.internalIPv4) &&
		lni.internalIPv6.Equal(other.internalIPv6) &&
		lni.ipv4AllocCIDR == other.ipv4AllocCIDR &&
		lni.ipv6AllocCIDR == other.ipv6AllocCIDR {
		return true
	}
	return false
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
	params *reconcilerParams,
	updateRules func(state desiredState, firstInit bool) error,
	updateProxyRules func(proxyPort uint16, localOnly bool, name string) error,
) error {
	// The minimum interval between reconciliation attempts
	const minReconciliationInterval = 200 * time.Millisecond

	state := desiredState{
		installRules: installIptRules,
		proxies:      make(map[string]proxyInfo),
		noTrackPods:  sets.New[noTrackPodInfo](),
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	localNodeEvents := stream.ToChannel(ctx, params.localNodeStore)
	state.localNodeInfo = toLocalNodeInfo(<-localNodeEvents)

	devices, devicesWatch := tables.SelectedDevices(params.devices, params.db.ReadTxn())
	state.devices = sets.New(tables.DeviceNames(devices)...)

	// Use a ticker to limit how often the desired state is reconciled to avoid doing
	// lots of operations when e.g. ipset updates.
	ticker := time.NewTicker(minReconciliationInterval)
	defer ticker.Stop()

	// stateChanged is true when the desired state has changed or when reconciling it
	// has failed. It's set to false when reconciling succeeds.
	stateChanged := true

	firstInit := true

	if err := updateRules(state, firstInit); err != nil {
		health.Degraded("iptables rules update failed", err)
		// Keep stateChanged=true and firstInit=true to try again on the next tick.
	} else {
		health.OK("iptables rules update completed")
		firstInit = false
		stateChanged = false
	}

stop:
	for {
		select {
		case <-ctx.Done():
			break stop
		case <-devicesWatch:
			devices, devicesWatch = tables.SelectedDevices(params.devices, params.db.ReadTxn())
			newDevices := sets.New(tables.DeviceNames(devices)...)
			if newDevices.Equal(state.devices) {
				continue
			}
			state.devices = newDevices
			stateChanged = true
		case localNode, ok := <-localNodeEvents:
			if !ok {
				break stop
			}
			localNodeInfo := toLocalNodeInfo(localNode)
			if localNodeInfo.equal(state.localNodeInfo) {
				continue
			}
			state.localNodeInfo = localNodeInfo
			stateChanged = true
		case newProxyInfo, ok := <-params.proxies:
			if !ok {
				break stop
			}
			if info, ok := state.proxies[newProxyInfo.name]; ok && info == newProxyInfo {
				continue
			}

			// if existing, previous rules related to the previous entry for the same proxy name
			// will be deleted by the manager (see Manager.addProxyRules)
			state.proxies[newProxyInfo.name] = newProxyInfo

			if !firstInit {
				// first init not yet completed, proxy rules will be updated as part of that
				stateChanged = true
				continue
			}

			if err := updateProxyRules(newProxyInfo.port, newProxyInfo.isLocalOnly, newProxyInfo.name); err != nil {
				log.WithError(err).Warning("iptables proxy rules incremental update failed, will retry a full reconciliation")
				// incremental rules update failed, schedule a full iptables reconciliation
				stateChanged = true
			}
		case noTrackPod, ok := <-params.addNoTrackPod:
			if !ok {
				break stop
			}
			if state.noTrackPods.Has(noTrackPod) {
				continue
			}
			state.noTrackPods.Insert(noTrackPod)
			stateChanged = true
		case noTrackPod, ok := <-params.delNoTrackPod:
			if !ok {
				break stop
			}
			if !state.noTrackPods.Has(noTrackPod) {
				continue
			}
			state.noTrackPods.Delete(noTrackPod)
			stateChanged = true
		case <-ticker.C:
			if !stateChanged {
				continue
			}

			if err := updateRules(state, firstInit); err != nil {
				log.WithError(err).Warning("iptables rules full reconciliation failed, will retry a full reconciliation")
				health.Degraded("iptables rules full reconciliation failed", err)
				// Keep stateChanged=true to try again on the next tick.
			} else {
				health.OK("iptables rules full reconciliation completed")
				firstInit = false
				stateChanged = false
			}
		}
	}

	cancel()

	// drain channels
	for range localNodeEvents {
	}
	for range params.proxies {
	}
	for range params.addNoTrackPod {
	}
	for range params.delNoTrackPod {
	}

	return nil
}
