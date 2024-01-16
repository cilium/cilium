// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/rate"
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
	health cell.HealthReporter,
	installIptRules bool,
	params *reconcilerParams,
	updateRules func(ctx context.Context, state desiredState, firstInit bool) error,
) error {
	state := desiredState{
		installRules: installIptRules,
		proxies:      sets.New[proxyInfo](),
		ipv4Set:      sets.New[netip.Addr](),
		ipv6Set:      sets.New[netip.Addr](),
		noTrackPods:  sets.New[noTrackPodInfo](),
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	localNodeEvents := stream.ToChannel(ctx, params.localNodeStore)
	state.localNodeInfo = toLocalNodeInfo(<-localNodeEvents)

	devices, devicesWatch := tables.SelectedDevices(params.devices, params.db.ReadTxn())
	state.devices = sets.New(tables.DeviceNames(devices)...)

	log.WithField("state", state).Info("updating rules to reconcile state")

	if err := updateRules(ctx, state, true); err != nil {
		health.Degraded("iptables rules installation failed", err)
	} else {
		health.OK("iptables rules installation completed")
	}

	limiter := rate.NewLimiter(time.Second, 1)
	defer limiter.Stop()

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
		case localNode, ok := <-localNodeEvents:
			if !ok {
				break stop
			}
			localNodeInfo := toLocalNodeInfo(localNode)
			if localNodeInfo.equal(state.localNodeInfo) {
				continue
			}
			state.localNodeInfo = localNodeInfo
		case proxyInfo, ok := <-params.proxies:
			if !ok {
				break stop
			}
			if state.proxies.Has(proxyInfo) {
				continue
			}
			state.proxies.Insert(proxyInfo)
		case ip, ok := <-params.addIPInSet:
			if !ok {
				break stop
			}
			if state.ipv6Set.Has(ip) || state.ipv4Set.Has(ip) {
				continue
			}
			if ip.Is6() {
				state.ipv6Set[ip] = sets.Empty{}
			} else {
				state.ipv4Set[ip] = sets.Empty{}
			}
		case ip, ok := <-params.delIPFromSet:
			if !ok {
				break stop
			}
			if !state.ipv6Set.Has(ip) && !state.ipv4Set.Has(ip) {
				continue
			}
			if ip.Is6() {
				delete(state.ipv6Set, ip)
			} else {
				delete(state.ipv4Set, ip)
			}
		case noTrackPod, ok := <-params.addNoTrackPod:
			if !ok {
				break stop
			}
			if state.noTrackPods.Has(noTrackPod) {
				continue
			}
			state.noTrackPods[noTrackPod] = sets.Empty{}
		case noTrackPod, ok := <-params.delNoTrackPod:
			if !ok {
				break stop
			}
			if !state.noTrackPods.Has(noTrackPod) {
				continue
			}
			delete(state.noTrackPods, noTrackPod)
		}

		if err := updateRules(ctx, state, false); err != nil {
			health.Degraded("iptables rules update failed", err)
		} else {
			health.OK("iptables rules update completed")
		}

		if err := limiter.Wait(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
	}

	cancel()

	// drain local node info channel
	for range localNodeEvents {
	}

	return nil
}
