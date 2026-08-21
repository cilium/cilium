// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eswitch_sriov

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// bridgeParamSpecs maps a recognized EswitchBridgeConfig.Params key to a
// setter (bake the parsed bool into a *netlink.Bridge before creation) and
// a getter (read the current live value back off a *netlink.Bridge), used
// by setBridgeParams and diffBridgeParams respectively.
//
// Only params representable in the vendored netlink.Bridge struct
// (MulticastSnooping, VlanFiltering, AgeingTime, HelloTime,
// VlanDefaultPVID, GroupFwdMask) are supported here. Notably absent:
// stp_state and mcast_stats_enabled — the kernel exposes these via
// IFLA_BR_STP_STATE / IFLA_BR_MCAST_STATS_ENABLED, but the vendored
// vishvananda/netlink does not yet surface them as Bridge fields.
// Adding support for them would require patching the vendored library (or hand
// building the netlink attribute) — not done here.
var bridgeParamSpecs = map[string]struct {
	set func(*netlink.Bridge, bool)
	get func(*netlink.Bridge) *bool
}{
	"vlan_filtering": {
		set: func(br *netlink.Bridge, b bool) { br.VlanFiltering = &b },
		get: func(br *netlink.Bridge) *bool { return br.VlanFiltering },
	},
	"multicast_snooping": {
		set: func(br *netlink.Bridge, b bool) { br.MulticastSnooping = &b },
		get: func(br *netlink.Bridge) *bool { return br.MulticastSnooping },
	},
}

// setBridgeParams decodes each configured EswitchBridgeConfig.Params entry
// and applies it directly onto br (an in-memory *netlink.Bridge that has
// not yet been created via LinkAdd). Unrecognized keys are rejected here
// (at reconcile time), not at CRD admission time.
//
// This is only ever called before the bridge exists / before it is brought
// up: real switchdev hardware (mlx5) rejects toggling params such as
// vlan_filtering via LinkModify once the bridge has ports enslaved to it
// (RTNETLINK "invalid argument"), so params must be baked into the initial
// LinkAdd request rather than applied afterwards.
func setBridgeParams(br *netlink.Bridge, params map[string]string) error {
	for k, v := range params {
		spec, ok := bridgeParamSpecs[k]
		if !ok {
			return fmt.Errorf("%q: %w", k, errUnknownBridgeParam)
		}

		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("invalid value %q for %s: %w", v, k, err)
		}

		spec.set(br, b)
	}

	return nil
}

// diffBridgeParams compares cfg's configured params against the live
// values already set on br (read from the kernel, e.g. via LinkByName) and
// returns a human-readable list of "key: configured=X live=Y" strings for
// every key whose value differs. An empty result means the live bridge
// already matches the configuration. Unrecognized keys are rejected the
// same way setBridgeParams rejects them.
func diffBridgeParams(br *netlink.Bridge, params map[string]string) ([]string, error) {
	var diffs []string

	for k, v := range params {
		spec, ok := bridgeParamSpecs[k]
		if !ok {
			return nil, fmt.Errorf("%q: %w", k, errUnknownBridgeParam)
		}

		want, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid value %q for %s: %w", v, k, err)
		}

		got := spec.get(br)
		if got == nil || *got != want {
			gotStr := "unknown"
			if got != nil {
				gotStr = strconv.FormatBool(*got)
			}
			diffs = append(diffs, fmt.Sprintf("%s: configured=%s live=%s", k, v, gotStr))
		}
	}

	return diffs, nil
}

// attachToBridge attaches link to the bridge, skipping the call if link is already
// attached to it (idempotent).
func (mgr *EswitchSRIOVManager) attachToBridge(link, master netlink.Link) error {
	if link.Attrs().MasterIndex == master.Attrs().Index {
		return nil
	}

	if err := mgr.nl.LinkSetMaster(link, master); err != nil {
		return err
	}

	return mgr.nl.LinkSetUp(link)
}

// reconcileBridge creates the named bridge if it doesn't already exist and
// applies its configured Params. If the bridge has already been reconciled
// earlier in the init() pass, the existing link is
// returned without redoing the work.
//
// Params are only ever applied at bridge-creation time, before the bridge
// is brought up: real switchdev hardware (mlx5) rejects toggling params
// such as vlan_filtering via LinkModify once ports are already enslaved to
// the bridge (RTNETLINK "invalid argument"), and by the time a pre-existing
// bridge is found here it may already have ports attached from a prior
// init() pass. So for a pre-existing bridge, reconcileBridge does NOT call
// LinkModify at all — it only compares the live params against the
// configured ones and logs any delta, so a config change is visible in the
// logs even though it isn't applied automatically (the agent would need to
// be restarted after the bridge is manually deleted/recreated, or the ports
// manually unenslaved, to pick up a changed param).
func (mgr *EswitchSRIOVManager) reconcileBridge(l *slog.Logger, cfg v2alpha1.EswitchBridgeConfig, reconciled map[string]struct{}) (netlink.Link, error) {
	if _, done := reconciled[cfg.Name]; done {
		return mgr.nl.LinkByName(cfg.Name)
	}

	link, err := mgr.nl.LinkByName(cfg.Name)
	if err != nil {
		br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: cfg.Name}}
		if err := setBridgeParams(br, cfg.Params); err != nil {
			return nil, fmt.Errorf("bridge %s: %w", cfg.Name, err)
		}

		if err := mgr.nl.LinkAdd(br); err != nil {
			return nil, fmt.Errorf("failed to create bridge %s: %w: %w", cfg.Name, err, errBridgeReconcile)
		}

		link, err = mgr.nl.LinkByName(cfg.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve newly created bridge %s: %w", cfg.Name, err)
		}

		l.Info("created bridge with configured params", logfields.Device, cfg.Name)
	} else {
		br, ok := link.(*netlink.Bridge)
		if !ok {
			return nil, fmt.Errorf("link %s exists but is not a bridge: %w", cfg.Name, errBridgeReconcile)
		}

		if diffs, err := diffBridgeParams(br, cfg.Params); err != nil {
			return nil, fmt.Errorf("bridge %s: %w", cfg.Name, err)
		} else if len(diffs) > 0 {
			l.Warn(
				"bridge already exists with params that differ from configuration; "+
					"params are only applied at bridge-creation time and will NOT be changed "+
					"on this existing bridge",
				logfields.Device, cfg.Name,
				logfields.Params, diffs,
			)
		}
	}

	if err := mgr.nl.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("failed to bring up bridge %s: %w", cfg.Name, err)
	}

	l.Info("reconciled bridge", logfields.Device, cfg.Name)
	reconciled[cfg.Name] = struct{}{}

	return link, nil
}

// bounceBridgeMembership detaches link from bridgeName and immediately
// re-attaches it. This is required as an unconditional step before every
// BridgeVlanAdd call on some switchdev NICs (observed on Mellanox/ConnectX
// representors, mlx5_core driver): the driver occasionally rejects a VLAN
// add with EINVAL even though the live bridge VLAN table read back via
// BridgeVlanList is fully consistent with the request (e.g. immediately
// after enslavement, or after a prior VLAN add/remove on the same port).
//
// This is a workaround to what seems to be a firmware race.
//
// bridgeName must be the current bridge master's name; if link is not
// currently enslaved to it (e.g. bridgeName is empty), this is a no-op.
func bounceBridgeMembership(nl netlinkOps, link netlink.Link, bridgeName string) error {
	if bridgeName == "" {
		return nil
	}

	master, err := nl.LinkByName(bridgeName)
	if err != nil {
		return fmt.Errorf("failed to retrieve bridge link %s: %w", bridgeName, err)
	}

	if err := nl.LinkSetNoMaster(link); err != nil {
		return fmt.Errorf("failed to detach %s from bridge %s: %w", link.Attrs().Name, bridgeName, err)
	}

	if err := nl.LinkSetMaster(link, master); err != nil {
		return fmt.Errorf("failed to re-attach %s to bridge %s: %w", link.Attrs().Name, bridgeName, err)
	}

	return nil
}

// bridgeVlanIsPVID queries the live bridge VLAN table and reports whether
// vid is currently configured as link's PVID (regardless of untagged
// status). Any error from the dump is treated as "not the PVID" so callers
// still attempt the (possibly redundant) mutating call rather than silently
// skipping it.
func bridgeVlanIsPVID(nl netlinkOps, link netlink.Link, vid uint16) bool {
	table, err := nl.BridgeVlanList()
	if err != nil {
		return false
	}

	for _, i := range table[int32(link.Attrs().Index)] {
		if i.Vid == vid && i.PortVID() {
			return true
		}
	}

	return false
}

// bridgeVlanPresent queries the live bridge VLAN table (source of truth)
// and reports whether vid is already configured as a PVID+untagged member
// on link. Any error from the dump is treated as "not present" so callers
// still attempt the (possibly redundant) mutating call rather than silently
// skipping it.
func bridgeVlanPresent(nl netlinkOps, link netlink.Link, vid uint16) bool {
	table, err := nl.BridgeVlanList()
	if err != nil {
		return false
	}

	infos, ok := table[int32(link.Attrs().Index)]
	if !ok {
		return false
	}

	for _, i := range infos {
		if i.Vid == vid && i.PortVID() && i.EngressUntag() {
			return true
		}
	}

	return false
}
