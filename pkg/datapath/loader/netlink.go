// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/inctimer"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
)

type baseDeviceMode string

const (
	directMode = baseDeviceMode("direct")
	tunnelMode = baseDeviceMode("tunnel")
)

func directionToParent(dir string) uint32 {
	switch dir {
	case dirIngress:
		return netlink.HANDLE_MIN_INGRESS
	case dirEgress:
		return netlink.HANDLE_MIN_EGRESS
	}
	return 0
}

func replaceQdisc(link netlink.Link) error {
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	return netlink.QdiscReplace(qdisc)
}

type progDefinition struct {
	progName  string
	direction string
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
func replaceDatapath(ctx context.Context, ifName, objPath string, progs []progDefinition, xdpMode string) (func(), error) {
	// Avoid unnecessarily loading a prog.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("getting interface %s by name: %w", ifName, err)
	}

	l := log.WithField("device", ifName).WithField("objPath", objPath).
		WithField("ifindex", link.Attrs().Index)

	// Load the ELF from disk.
	l.Debug("Loading CollectionSpec from ELF")
	spec, err := bpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("loading eBPF ELF: %w", err)
	}

	for _, prog := range progs {
		if spec.Programs[prog.progName] == nil {
			return nil, fmt.Errorf("no program %s found in eBPF ELF", prog.progName)
		}
	}

	// Load the CollectionSpec into the kernel, picking up any pinned maps from
	// bpffs in the process.
	finalize := func() {}
	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
	}
	l.Debug("Loading Collection into kernel")
	coll, err := bpf.LoadCollection(spec, opts)
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		// Temporarily rename bpffs pins of maps whose definitions have changed in
		// a new version of a datapath ELF.
		l.Debug("Starting bpffs map migration")
		if err := bpf.StartBPFFSMigration(bpf.TCGlobalsPath(), spec); err != nil {
			return nil, fmt.Errorf("Failed to start bpffs map migration: %w", err)
		}

		finalize = func() {
			l.Debug("Finalizing bpffs map migration")
			if err := bpf.FinalizeBPFFSMigration(bpf.TCGlobalsPath(), spec, false); err != nil {
				l.WithError(err).Error("Could not finalize bpffs map migration")
			}
		}

		// Retry loading the Collection after starting map migration.
		l.Debug("Retrying loading Collection into kernel after map migration")
		coll, err = bpf.LoadCollection(spec, opts)
	}
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		if _, err := fmt.Fprintf(os.Stderr, "Verifier error: %s\nVerifier log: %+v\n", err, ve); err != nil {
			return nil, fmt.Errorf("writing verifier log to stderr: %w", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("loading eBPF collection into the kernel: %w", err)
	}
	defer coll.Close()

	// Avoid attaching a prog to a stale interface.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	for _, prog := range progs {
		scopedLog := l.WithField("progName", prog.progName).WithField("direction", prog.direction)
		scopedLog.Debug("Attaching program to interface")
		if err := attachProgram(link, coll.Programs[prog.progName], prog.progName, directionToParent(prog.direction), xdpModeToFlag(xdpMode)); err != nil {
			// Program replacement unsuccessful, revert bpffs migration.
			l.Debug("Reverting bpffs map migration")
			if err := bpf.FinalizeBPFFSMigration(bpf.TCGlobalsPath(), spec, true); err != nil {
				l.WithError(err).Error("Failed to revert bpffs map migration")
			}

			return nil, fmt.Errorf("program %s: %w", prog.progName, err)
		}
		scopedLog.Debug("Successfully attached program to interface")
	}

	return finalize, nil
}

// attachProgram attaches prog to link.
// If xdpFlags is non-zero, attaches prog to XDP.
func attachProgram(link netlink.Link, prog *ebpf.Program, progName string, qdiscParent uint32, xdpFlags uint32) error {
	if prog == nil {
		return errors.New("cannot attach a nil program")
	}

	if xdpFlags != 0 {
		// Omitting XDP_FLAGS_UPDATE_IF_NOEXIST equals running 'ip' with -force,
		// and will clobber any existing XDP attachment to the interface.
		if err := netlink.LinkSetXdpFdWithFlags(link, prog.FD(), int(xdpFlags)); err != nil {
			return fmt.Errorf("attaching XDP program to interface %s: %w", link.Attrs().Name, err)
		}

		return nil
	}

	if err := replaceQdisc(link); err != nil {
		return fmt.Errorf("replacing clsact qdisc for interface %s: %w", link.Attrs().Name, err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    qdiscParent,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  option.Config.TCFilterPriority,
		},
		Fd:           prog.FD(),
		Name:         fmt.Sprintf("%s-%s", progName, link.Attrs().Name),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("replacing tc filter: %w", err)
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

// SetupBaseDevice decides which and what kind of interfaces should be set up as
// the first step of datapath initialization, then performs the setup (and
// creation, if needed) of those interfaces. It returns two links and an error.
// By default, it sets up the veth pair - cilium_host and cilium_net.
func SetupBaseDevice(mtu int) (netlink.Link, netlink.Link, error) {
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

// reloadIPSecOnLinkChanges subscribes to link changes to detect newly added devices
// and reinitializes IPsec on changes. Only in effect for ENI mode in which we expect
// new devices at runtime.
func (l *Loader) reloadIPSecOnLinkChanges() {
	// settleDuration is the amount of time to wait for further link updates
	// before proceeding with reinitialization. This avoids back-to-back
	// reinitialization when multiple link changes are made at once.
	const settleDuration = 1 * time.Second

	if !option.Config.EnableIPSec || option.Config.IPAM != ipamOption.IPAMENI {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	updates := make(chan netlink.LinkUpdate)

	if err := netlink.LinkSubscribe(updates, ctx.Done()); err != nil {
		log.WithError(err).Fatal("Failed to subscribe for link changes")
	}

	go func() {
		defer cancel()

		timer, stop := inctimer.New()
		defer stop()

		// If updates arrive during settle duration a single element
		// is sent to this channel and we reinitialize right away
		// without waiting for further updates.
		trigger := make(chan struct{}, 1)

		for {
			// Wait for first update or trigger before reinitializing.
			select {
			case _, ok := <-updates:
				if !ok {
					return
				}
			case <-trigger:
			}

			log.Info("Reinitializing IPsec due to link changes")
			err := l.reinitializeIPSec(ctx)
			if err != nil {
				// We may fail if links have been removed during the reload. In this case
				// the updates channel will have queued updates which will retrigger the
				// reinitialization.
				log.WithError(err).Warn("Failed to reinitialize IPsec after device change")
			}

			// Avoid reinitializing repeatedly in short period of time
			// by draining further updates for 'settleDuration'.
			settled := timer.After(settleDuration)
		settleLoop:
			for {
				select {
				case <-settled:
					break settleLoop
				case <-updates:
					select {
					case trigger <- struct{}{}:
					default:
					}
					break settleLoop
				}

			}
		}
	}()
}
