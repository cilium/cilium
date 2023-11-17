// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/inctimer"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/cilium/cilium/pkg/time"
)

const qdiscClsact = "clsact"

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
		QdiscType:  qdiscClsact,
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
func replaceDatapath(ctx context.Context, ifName, objPath string, progs []progDefinition, xdpMode string) (_ func(), err error) {
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

	revert := func() {
		// Program replacement unsuccessful, revert bpffs migration.
		l.Debug("Reverting bpffs map migration")
		if err := bpf.FinalizeBPFFSMigration(bpf.TCGlobalsPath(), spec, true); err != nil {
			l.WithError(err).Error("Failed to revert bpffs map migration")
		}
	}

	for _, prog := range progs {
		if spec.Programs[prog.progName] == nil {
			return nil, fmt.Errorf("no program %s found in eBPF ELF", prog.progName)
		}
	}

	// Unconditionally repin cilium_calls_* maps to prevent them from being
	// repopulated by the loader.
	for key, ms := range spec.Maps {
		if !strings.HasPrefix(ms.Name, "cilium_calls_") {
			continue
		}

		if err := bpf.RepinMap(bpf.TCGlobalsPath(), key, ms); err != nil {
			return nil, fmt.Errorf("repinning map %s: %w", key, err)
		}

		defer func() {
			revert := false
			// This captures named return variable err.
			if err != nil {
				revert = true
			}

			if err := bpf.FinalizeMap(bpf.TCGlobalsPath(), key, revert); err != nil {
				l.WithError(err).Error("Could not finalize map")
			}
		}()

		// Only one cilium_calls_* per collection, we can stop here.
		break
	}

	// Inserting a program into these maps will immediately cause other BPF
	// programs to call into it, even if other maps like cilium_calls haven't been
	// fully populated for the current ELF. Save their contents and avoid sending
	// them to the ELF loader.
	var policyProgs, egressPolicyProgs []ebpf.MapKV
	if pm, ok := spec.Maps[policymap.PolicyCallMapName]; ok {
		policyProgs = append(policyProgs, pm.Contents...)
		pm.Contents = nil
	}
	if pm, ok := spec.Maps[policymap.PolicyEgressCallMapName]; ok {
		egressPolicyProgs = append(egressPolicyProgs, pm.Contents...)
		pm.Contents = nil
	}

	// Load the CollectionSpec into the kernel, picking up any pinned maps from
	// bpffs in the process.
	finalize := func() {}
	pinPath := bpf.TCGlobalsPath()
	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	}
	if err := bpf.MkdirBPF(pinPath); err != nil {
		return nil, fmt.Errorf("creating bpffs pin path: %w", err)
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
		if xdpMode != "" {
			linkDir := bpffsDeviceLinksDir(bpf.CiliumPath(), link)
			if err := bpf.MkdirBPF(linkDir); err != nil {
				return nil, fmt.Errorf("creating bpffs link dir for device %s: %w", link.Attrs().Name, err)
			}

			scopedLog.Debug("Attaching XDP program to interface")
			err = attachXDPProgram(link, coll.Programs[prog.progName], prog.progName, linkDir, xdpModeToFlag(xdpMode))
		} else {
			scopedLog.Debug("Attaching TC program to interface")
			err = attachTCProgram(link, coll.Programs[prog.progName], prog.progName, directionToParent(prog.direction))
		}

		if err != nil {
			revert()
			return nil, fmt.Errorf("program %s: %w", prog.progName, err)
		}
		scopedLog.Debug("Successfully attached program to interface")
	}

	// If an ELF contains one of the policy call maps, resolve and insert the
	// programs it refers to into the map.

	if len(policyProgs) != 0 {
		if err := resolveAndInsertCalls(coll, policymap.PolicyCallMapName, policyProgs); err != nil {
			revert()
			return nil, fmt.Errorf("inserting policy programs: %w", err)
		}
	}

	if len(egressPolicyProgs) != 0 {
		if err := resolveAndInsertCalls(coll, policymap.PolicyEgressCallMapName, egressPolicyProgs); err != nil {
			revert()
			return nil, fmt.Errorf("inserting egress policy programs: %w", err)
		}
	}

	return finalize, nil
}

// resolveAndInsertCalls resolves a given slice of ebpf.MapKV containing u32 keys
// and string values (typical for a prog array) to the Programs they point to in
// the Collection. The Programs are then inserted into the Map with the given
// mapName contained within the Collection.
func resolveAndInsertCalls(coll *ebpf.Collection, mapName string, calls []ebpf.MapKV) error {
	m, ok := coll.Maps[mapName]
	if !ok {
		return fmt.Errorf("call map %s not found in Collection", mapName)
	}

	for _, v := range calls {
		name := v.Value.(string)
		slot := v.Key.(uint32)

		p, ok := coll.Programs[name]
		if !ok {
			return fmt.Errorf("program %s not found in Collection", name)
		}

		if err := m.Update(slot, p, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("inserting program %s into slot %d", name, slot)
		}

		log.Debugf("Inserted program %s into %s slot %d", name, mapName, slot)
	}

	return nil
}

// attachTCProgram attaches the TC program 'prog' to link.
func attachTCProgram(link netlink.Link, prog *ebpf.Program, progName string, qdiscParent uint32) error {
	if prog == nil {
		return errors.New("cannot attach a nil program")
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
		return fmt.Errorf("replacing tc filter for interface %s: %w", link.Attrs().Name, err)
	}

	return nil
}

// removeTCFilters removes all tc filters from the given interface.
// Direction is passed as netlink.HANDLE_MIN_{INGRESS,EGRESS} via tcDir.
func removeTCFilters(ifName string, tcDir uint32) error {
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

// enableForwarding puts the given link into the up state and enables IP forwarding.
func enableForwarding(link netlink.Link) error {
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
	if err := enableForwarding(veth); err != nil {
		return err
	}
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		return err
	}
	if err := enableForwarding(peer); err != nil {
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
		getUpdate:
			select {
			case u, ok := <-updates:
				if !ok {
					return
				}
				// Ignore veth devices
				if u.Type() == "veth" {
					goto getUpdate
				}
			case <-trigger:
			}

			log.Info("Reinitializing IPsec due to device changes")
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
				case u := <-updates:
					// Ignore veth devices
					if u.Type() == "veth" {
						continue
					}

					// Trigger reinit immediately after
					// settle duration has passed.
					select {
					case trigger <- struct{}{}:
					default:
					}
				}

			}
		}
	}()
}

// addHostDeviceAddr add internal ipv4 and ipv6 addresses to the cilium_host device.
func addHostDeviceAddr(hostDev netlink.Link, ipv4, ipv6 net.IP) error {
	if ipv4 != nil {
		addr := netlink.Addr{
			IPNet: &net.IPNet{
				IP:   ipv4,
				Mask: net.CIDRMask(32, 32), // corresponds to /32
			},
		}

		if err := netlink.AddrReplace(hostDev, &addr); err != nil {
			return err
		}
	}
	if ipv6 != nil {
		addr := netlink.Addr{
			IPNet: &net.IPNet{
				IP:   ipv6,
				Mask: net.CIDRMask(128, 128), // corresponds to /128
			},
		}

		if err := netlink.AddrReplace(hostDev, &addr); err != nil {
			return err
		}

	}
	return nil
}

// setupTunnelDevice ensures the cilium_{mode} device is created and
// unused leftover devices are cleaned up in case mode changes.
func setupTunnelDevice(mode tunnel.Protocol, port uint16, mtu int) error {
	switch mode {
	case tunnel.Geneve:
		if err := setupGeneveDevice(port, mtu); err != nil {
			return fmt.Errorf("setting up geneve device: %w", err)
		}
		if err := removeDevice(defaults.VxlanDevice); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.VxlanDevice, err)
		}

	case tunnel.VXLAN:
		if err := setupVxlanDevice(port, mtu); err != nil {
			return fmt.Errorf("setting up vxlan device: %w", err)
		}
		if err := removeDevice(defaults.GeneveDevice); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.GeneveDevice, err)
		}

	default:
		if err := removeDevice(defaults.VxlanDevice); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.VxlanDevice, err)
		}
		if err := removeDevice(defaults.GeneveDevice); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.GeneveDevice, err)
		}
	}

	return nil
}

// setupGeneveDevice ensures the cilium_geneve device is created with the given
// destination port and mtu.
//
// Changing the destination port will recreate the device. Changing the MTU will
// modify the device without recreating it.
func setupGeneveDevice(dport uint16, mtu int) error {
	mac, err := mac.GenerateRandMAC()
	if err != nil {
		return err
	}

	dev := &netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name:         defaults.GeneveDevice,
			MTU:          mtu,
			HardwareAddr: net.HardwareAddr(mac),
		},
		FlowBased: true,
		Dport:     dport,
	}

	l, err := ensureDevice(dev)
	if err != nil {
		return fmt.Errorf("creating geneve device: %w", err)
	}

	// Recreate the device with the correct destination port. Modifying the device
	// without recreating it is not supported.
	geneve, _ := l.(*netlink.Geneve)
	if geneve.Dport != dport {
		if err := netlink.LinkDel(l); err != nil {
			return fmt.Errorf("deleting outdated geneve device: %w", err)
		}
		if _, err := ensureDevice(dev); err != nil {
			return fmt.Errorf("recreating geneve device %s: %w", defaults.GeneveDevice, err)
		}
	}

	return nil
}

// setupVxlanDevice ensures the cilium_vxlan device is created with the given
// port and mtu.
//
// Changing the port will recreate the device. Changing the MTU will modify the
// device without recreating it.
func setupVxlanDevice(port uint16, mtu int) error {
	mac, err := mac.GenerateRandMAC()
	if err != nil {
		return err
	}

	dev := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:         defaults.VxlanDevice,
			MTU:          mtu,
			HardwareAddr: net.HardwareAddr(mac),
		},
		FlowBased: true,
		Port:      int(port),
	}

	l, err := ensureDevice(dev)
	if err != nil {
		return fmt.Errorf("creating vxlan device: %w", err)
	}

	// Recreate the device with the correct destination port. Modifying the device
	// without recreating it is not supported.
	vxlan, _ := l.(*netlink.Vxlan)
	if vxlan.Port != int(port) {
		if err := netlink.LinkDel(l); err != nil {
			return fmt.Errorf("deleting outdated vxlan device: %w", err)
		}
		if _, err := ensureDevice(dev); err != nil {
			return fmt.Errorf("recreating vxlan device %s: %w", defaults.VxlanDevice, err)
		}
	}

	return nil
}

// setupIPIPDevices ensures the specified v4 and/or v6 devices are created and
// configured with their respective sysctls.
//
// Calling this function may result in tunl0 (v4) or ip6tnl0 (v6) fallback
// interfaces being created as a result of loading the ipip and ip6_tunnel
// kernel modules by creating cilium_ tunnel interfaces. These are catch-all
// interfaces for the ipip decapsulation stack. By default, these interfaces
// will be created in new network namespaces, but Cilium disables this behaviour
// by setting net.core.fb_tunnels_only_for_init_net = 2.
//
// In versions of Cilium prior to 1.15, the behaviour was as follows:
//   - Repurpose the default tunl0 by setting it into collect_md mode and renaming
//     it to cilium_ipip4. Use the interface for production traffic.
//   - The same cannot be done for ip6tunl0, as collect_md cannot be enabled on
//     this interface. Leave it unused.
//   - Rename sit0 to cilium_sit, if present. This was potentially a mistake,
//     as the sit module is not involved with ip6tnl interfaces.
//
// As of Cilium 1.15, if present, tunl0 is renamed to cilium_tunl and ip6tnl0 is
// renamed to cilium_ip6tnl. This is to communicate to the user that Cilium has
// taken control of the encapsulation stack on the node, as it currently doesn't
// explicitly support sharing it with other tools/CNIs. Fallback devices are left
// unused for production traffic. Only devices that were explicitly created are used.
func setupIPIPDevices(ipv4, ipv6 bool) error {
	// FlowBased sets IFLA_IPTUN_COLLECT_METADATA, the equivalent of 'ip link add
	// ... type ipip/ip6tnl external'. This is needed so bpf programs can use
	// bpf_skb_[gs]et_tunnel_key() on packets flowing through tunnels.

	if ipv4 {
		// Set up IPv4 tunnel device if requested.
		if _, err := ensureDevice(&netlink.Iptun{
			LinkAttrs: netlink.LinkAttrs{Name: defaults.IPIPv4Device},
			FlowBased: true,
		}); err != nil {
			return fmt.Errorf("creating %s: %w", defaults.IPIPv4Device, err)
		}

		// Rename fallback device created by potential kernel module load after
		// creating tunnel interface.
		if err := renameDevice("tunl0", "cilium_tunl"); err != nil {
			return fmt.Errorf("renaming fallback device %s: %w", "tunl0", err)
		}
	} else {
		if err := removeDevice(defaults.IPIPv4Device); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.IPIPv4Device, err)
		}
	}

	if ipv6 {
		// Set up IPv6 tunnel device if requested.
		if _, err := ensureDevice(&netlink.Ip6tnl{
			LinkAttrs: netlink.LinkAttrs{Name: defaults.IPIPv6Device},
			FlowBased: true,
		}); err != nil {
			return fmt.Errorf("creating %s: %w", defaults.IPIPv6Device, err)
		}

		// Rename fallback device created by potential kernel module load after
		// creating tunnel interface.
		if err := renameDevice("ip6tnl0", "cilium_ip6tnl"); err != nil {
			return fmt.Errorf("renaming fallback device %s: %w", "tunl0", err)
		}
	} else {
		if err := removeDevice(defaults.IPIPv6Device); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.IPIPv6Device, err)
		}
	}

	return nil
}

// ensureDevice ensures a device with the given attrs is present on the system.
// If a device with the given name already exists, device creation is skipped and
// the existing device will be used as-is for the subsequent configuration steps.
// The device is never recreated.
//
// The device's state is set to 'up', L3 forwarding sysctls are applied, and MTU
// is set.
func ensureDevice(attrs netlink.Link) (netlink.Link, error) {
	name := attrs.Attrs().Name

	// Reuse existing tunnel interface created by previous runs.
	l, err := netlink.LinkByName(name)
	if err != nil {
		if err := netlink.LinkAdd(attrs); err != nil {
			return nil, fmt.Errorf("creating device %s: %w", name, err)
		}

		// Fetch the link we've just created.
		l, err = netlink.LinkByName(name)
		if err != nil {
			return nil, fmt.Errorf("retrieving created device %s: %w", name, err)
		}
	}

	if err := enableForwarding(l); err != nil {
		return nil, fmt.Errorf("setting up device %s: %w", name, err)
	}

	// Update MTU on the link if necessary.
	wantMTU, gotMTU := attrs.Attrs().MTU, l.Attrs().MTU
	if wantMTU != 0 && wantMTU != gotMTU {
		if err := netlink.LinkSetMTU(l, wantMTU); err != nil {
			return nil, fmt.Errorf("setting MTU on %s: %w", name, err)
		}
	}

	return l, nil
}

// removeDevice removes the device with the given name. Returns error if the
// device exists but was unable to be removed.
func removeDevice(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("removing device %s: %w", name, err)
	}

	return nil
}

// renameDevice renames a network device from and to a given value. Returns nil
// if the device does not exist.
func renameDevice(from, to string) error {
	link, err := netlink.LinkByName(from)
	if err != nil {
		return nil
	}

	if err := netlink.LinkSetName(link, to); err != nil {
		return fmt.Errorf("renaming device %s to %s: %w", from, to, err)
	}

	return nil
}

// DeviceHasTCProgramLoaded checks whether a given device has tc filter/qdisc progs attached.
func DeviceHasTCProgramLoaded(hostInterface string, checkEgress bool) (bool, error) {
	const bpfProgPrefix = "cil_"

	l, err := netlink.LinkByName(hostInterface)
	if err != nil {
		return false, fmt.Errorf("unable to find endpoint link by name: %w", err)
	}

	dd, err := netlink.QdiscList(l)
	if err != nil {
		return false, fmt.Errorf("unable to fetch qdisc list for endpoint: %w", err)
	}
	var found bool
	for _, d := range dd {
		if d.Type() == qdiscClsact {
			found = true
			break
		}
	}
	if !found {
		return false, nil
	}

	ff, err := netlink.FilterList(l, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return false, fmt.Errorf("unable to fetch ingress filter list: %w", err)
	}
	var filtersCount int
	for _, f := range ff {
		if filter, ok := f.(*netlink.BpfFilter); ok {
			if strings.HasPrefix(filter.Name, bpfProgPrefix) {
				filtersCount++
			}
		}
	}
	if filtersCount == 0 {
		return false, nil
	}
	if !checkEgress {
		return true, nil
	}

	ff, err = netlink.FilterList(l, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return false, fmt.Errorf("unable to fetch egress filter list: %w", err)
	}
	filtersCount = 0
	for _, f := range ff {
		if filter, ok := f.(*netlink.BpfFilter); ok {
			if strings.HasPrefix(filter.Name, bpfProgPrefix) {
				filtersCount++
			}
		}
	}
	return len(ff) > 0 && filtersCount > 0, nil
}
