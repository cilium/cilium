// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2018 Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/inctimer"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type baseDeviceMode string

const (
	ipvlanMode = baseDeviceMode("ipvlan")
	directMode = baseDeviceMode("direct")
	tunnelMode = baseDeviceMode("tunnel")

	libbpfFixupMsg = "struct bpf_elf_map fixup performed due to size mismatch!"
)

func replaceQdisc(ifName string) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err = netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("netlink: Replacing qdisc for %s failed: %s", ifName, err)
	} else {
		log.Debugf("netlink: Replacing qdisc for %s succeeded", ifName)
	}

	return nil
}

// replaceDatapath replaces the qdisc and BPF program for an endpoint or XDP program.
//
// When successful, returns a finalizer to allow the map cleanup operation to be
// deferred by the caller. On error, any maps pending migration are immediately
// re-pinned to their original paths and a finalizer is not returned.
//
// When replacing multiple programs from the same ELF in a loop, the finalizer
// should only be run when all the interface's programs have been replaced
// since they might share one or more tail call maps.
//
// For example, this is the case with from-netdev and to-netdev. If eth0:to-netdev
// gets its program and maps replaced and unpinned, its eth0:from-netdev counterpart
// will miss tail calls (and drop packets) until it has been replaced as well.
func replaceDatapath(ctx context.Context, ifName, objPath, progSec, progDirection string, xdp bool, xdpMode string) (func(), error) {
	var (
		loaderProg string
		args       []string
	)

	if !xdp {
		if err := replaceQdisc(ifName); err != nil {
			return nil, fmt.Errorf("Failed to replace Qdisc for %s: %s", ifName, err)
		}
	}

	// Temporarily rename bpffs pins of maps whose definitions have changed in
	// a new version of a datapath ELF.
	if err := bpf.StartBPFFSMigration(bpf.MapPrefixPath(), objPath); err != nil {
		return nil, fmt.Errorf("Failed to start bpffs map migration: %w", err)
	}

	// FIXME: replace exec with native call
	if xdp {
		loaderProg = "ip"
		args = []string{"-force", "link", "set", "dev", ifName, xdpMode,
			"obj", objPath, "sec", progSec}
	} else {
		loaderProg = "tc"
		args = []string{"filter", "replace", "dev", ifName, progDirection,
			"prio", "1", "handle", "1", "bpf", "da", "obj", objPath,
			"sec", progSec,
		}
	}

	// If the iproute2 call below is successful, any 'pending' map pins will be removed.
	// If not, any pending maps will be re-pinned back to their initial paths.
	cmd := exec.CommandContext(ctx, loaderProg, args...).WithFilters(libbpfFixupMsg)
	if _, err := cmd.CombinedOutput(log, true); err != nil {
		// Program/object replacement unsuccessful, revert bpffs migration.
		if err := bpf.FinalizeBPFFSMigration(bpf.MapPrefixPath(), objPath, true); err != nil {
			return nil, fmt.Errorf("Failed to revert bpffs map migration: %w", err)
		}
		return nil, fmt.Errorf("Failed to load prog with %s: %w", loaderProg, err)
	}

	finalize := func() {
		l := log.WithField("device", ifName).WithField("objPath", objPath)
		l.Debug("Finalizing bpffs map migration")
		if err := bpf.FinalizeBPFFSMigration(bpf.MapPrefixPath(), objPath, false); err != nil {
			l.WithError(err).Error("Could not finalize bpffs map migration")
		}
	}

	return finalize, nil
}

// graftDatapath replaces obj in tail call map
func graftDatapath(ctx context.Context, mapPath, objPath, progSec string) error {
	if err := bpf.StartBPFFSMigration(bpf.MapPrefixPath(), objPath); err != nil {
		return fmt.Errorf("Failed to start bpffs map migration: %w", err)
	}

	var revert bool
	defer func() {
		if err := bpf.FinalizeBPFFSMigration(bpf.MapPrefixPath(), objPath, revert); err != nil {
			log.WithError(err).WithFields(logrus.Fields{logfields.BPFMapPath: mapPath, "objPath": objPath}).
				Error("Could not finalize bpffs map migration")
		}
	}()

	// FIXME: replace exec with native call
	// FIXME: only key 0 right now, could be made more flexible
	args := []string{"exec", "bpf", "graft", mapPath, "key", "0",
		"obj", objPath, "sec", progSec,
	}
	cmd := exec.CommandContext(ctx, "tc", args...).WithFilters(libbpfFixupMsg)
	if _, err := cmd.CombinedOutput(log, true); err != nil {
		revert = true
		return fmt.Errorf("Failed to graft tc object: %s", err)
	}

	return nil
}

// RemoveTCFilters removes all tc filters from the given interface.
// Direction is passed as netlink.HANDLE_MIN_{INGRESS,EGRESS} via tcDir.
func RemoveTCFilters(ifName string, tcDir uint32) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	filters, err := netlink.FilterList(link, tcDir)
	if err != nil {
		return err
	}

	for _, f := range filters {
		if err := netlink.FilterDel(f); err != nil {
			return err
		}
	}

	return nil
}

func setupDev(link netlink.Link) error {
	ifName := link.Attrs().Name

	if err := netlink.LinkSetUp(link); err != nil {
		log.WithError(err).WithField("device", ifName).Warn("Could not set up the link")
		return err
	}

	sysSettings := make([]sysctl.Setting, 0, 5)
	if option.Config.EnableIPv6 {
		sysSettings = append(sysSettings, sysctl.Setting{
			Name: fmt.Sprintf("net.ipv6.conf.%s.forwarding", ifName), Val: "1", IgnoreErr: false})
	}
	if option.Config.EnableIPv4 {
		sysSettings = append(sysSettings, []sysctl.Setting{
			{Name: fmt.Sprintf("net.ipv4.conf.%s.forwarding", ifName), Val: "1", IgnoreErr: false},
			{Name: fmt.Sprintf("net.ipv4.conf.%s.rp_filter", ifName), Val: "0", IgnoreErr: false},
			{Name: fmt.Sprintf("net.ipv4.conf.%s.accept_local", ifName), Val: "1", IgnoreErr: false},
			{Name: fmt.Sprintf("net.ipv4.conf.%s.send_redirects", ifName), Val: "0", IgnoreErr: false},
		}...)
	}
	if err := sysctl.ApplySettings(sysSettings); err != nil {
		return err
	}

	return nil
}

func setupVethPair(name, peerName string) error {
	// Create the veth pair if it doesn't exist.
	if _, err := netlink.LinkByName(name); err != nil {
		hostMac, err := mac.GenerateRandMAC()
		if err != nil {
			return err
		}
		peerMac, err := mac.GenerateRandMAC()
		if err != nil {
			return err
		}

		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name:         name,
				HardwareAddr: net.HardwareAddr(hostMac),
				TxQLen:       1000,
			},
			PeerName:         peerName,
			PeerHardwareAddr: net.HardwareAddr(peerMac),
		}
		if err := netlink.LinkAdd(veth); err != nil {
			return err
		}
	}

	veth, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if err := setupDev(veth); err != nil {
		return err
	}
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		return err
	}
	if err := setupDev(peer); err != nil {
		return err
	}

	return nil
}

func setupIpvlan(name string, nativeLink netlink.Link) (*netlink.IPVlan, error) {
	hostLink, err := netlink.LinkByName(name)
	if err == nil {
		// Ignore the error.
		netlink.LinkDel(hostLink)
	}

	ipvlan := &netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        name,
			ParentIndex: nativeLink.Attrs().Index,
			TxQLen:      1000,
		},
		Mode: netlink.IPVLAN_MODE_L3,
	}
	if err := netlink.LinkAdd(ipvlan); err != nil {
		return nil, err
	}

	if err := setupDev(ipvlan); err != nil {
		return nil, err
	}

	return ipvlan, nil
}

// setupBaseDevice decides which and what kind of interfaces should be set up as
// the first step of datapath initialization, then performs the setup (and
// creation, if needed) of those interfaces. It returns two links and an error.
// By default, it sets up the veth pair - cilium_host and cilium_net.
// In ipvlan mode, it creates the cilium_host ipvlan with the native device as a
// parent.
func setupBaseDevice(nativeDevs []netlink.Link, mode baseDeviceMode, mtu int) (netlink.Link, netlink.Link, error) {
	switch mode {
	case ipvlanMode:
		ipvlan, err := setupIpvlan(defaults.HostDevice, nativeDevs[0])
		if err != nil {
			return nil, nil, err
		}
		if err := netlink.LinkSetMTU(ipvlan, mtu); err != nil {
			return nil, nil, err
		}

		return ipvlan, ipvlan, nil
	default:
		if err := setupVethPair(defaults.HostDevice, defaults.SecondHostDevice); err != nil {
			return nil, nil, err
		}

		linkHost, err := netlink.LinkByName(defaults.HostDevice)
		if err != nil {
			return nil, nil, err
		}
		linkNet, err := netlink.LinkByName(defaults.SecondHostDevice)
		if err != nil {
			return nil, nil, err
		}

		if err := netlink.LinkSetARPOff(linkHost); err != nil {
			return nil, nil, err
		}
		if err := netlink.LinkSetARPOff(linkNet); err != nil {
			return nil, nil, err
		}

		if err := netlink.LinkSetMTU(linkHost, mtu); err != nil {
			return nil, nil, err
		}
		if err := netlink.LinkSetMTU(linkNet, mtu); err != nil {
			return nil, nil, err
		}

		return linkHost, linkNet, nil
	}
}

// reloadIPSecOnLinkChanges subscribes to link changes to detect newly added devices
// and reinitializes IPsec on changes. Only in effect for ENI mode in which we expect
// new devices at runtime.
func (l *Loader) reloadIPSecOnLinkChanges() {
	// settleDuration is the amount of time to wait for further link updates
	// before proceeding with reinitialization. This avoids reinitializing
	// twice when seeing NEWLINK followed by SETLINK.
	const settleDuration = 5 * time.Second

	if !option.Config.EnableIPSec || option.Config.IPAM != ipamOption.IPAMENI {
		return
	}

	updates := make(chan netlink.LinkUpdate, 16)
	ctx := context.Background()

	if err := netlink.LinkSubscribe(updates, ctx.Done()); err != nil {
		log.WithError(err).Fatal("Failed to subscribe for link changes")
	}

	go func() {
		timer, stop := inctimer.New()
		defer stop()

		for u := range updates {
			// Ignore updates about veth devices
			if u.Type() == "veth" {
				continue
			}

			// Drain extra updates while we wait for things to settle
			settled := false
			for !settled {
				select {
				case _, ok := <-updates:
					if !ok {
						return
					}
				case <-timer.After(settleDuration):
					settled = true
				}
			}

			err := l.reinitializeIPSec(ctx)
			if err != nil {
				// We may fail if links have been removed during the reload. In this case
				// the updates channel will have queued updates which will retrigger the
				// reinitialization.
				log.WithError(err).Warn("Failed to reinitialize IPsec after device change")
			}
		}
	}()
}
