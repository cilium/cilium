// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
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

// loadDatapath returns a Collection given the ELF obj, renames maps according
// to mapRenames and overrides the given constants.
//
// When successful, returns a function that commits pending map pins to the bpf
// file system, for maps that were found to be incompatible with their pinned
// counterparts, or for maps with certain flags that modify the default pinning
// behaviour.
//
// When attaching multiple programs from the same ELF in a loop, the returned
// function should only be run after all entrypoints have been attached. For
// example, attach both bpf_host.c:cil_to_netdev and cil_from_netdev before
// invoking the returned function, otherwise missing tail calls will occur.
func loadDatapath(spec *ebpf.CollectionSpec, mapRenames map[string]string, constants map[string]uint64) (*ebpf.Collection, func() error, error) {
	spec, err := renameMaps(spec, mapRenames)
	if err != nil {
		return nil, nil, err
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
	pinPath := bpf.TCGlobalsPath()
	collOpts := bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: pinPath},
		},
		Constants: constants,
	}
	if err := bpf.MkdirBPF(pinPath); err != nil {
		return nil, nil, fmt.Errorf("creating bpffs pin path: %w", err)
	}

	log.Debug("Loading Collection into kernel")

	coll, commit, err := bpf.LoadCollection(spec, &collOpts)
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		if _, err := fmt.Fprintf(os.Stderr, "Verifier error: %s\nVerifier log: %+v\n", err, ve); err != nil {
			return nil, nil, fmt.Errorf("writing verifier log to stderr: %w", err)
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("loading eBPF collection into the kernel: %w", err)
	}

	// If an ELF contains one of the policy call maps, resolve and insert the
	// programs it refers to into the map. This always needs to happen _before_
	// attaching the ELF's entrypoint(s), but after the ELF's internal tail call
	// map (cilium_calls) has been populated, as doing so means the ELF's programs
	// become reachable through its policy programs, which hold references to the
	// endpoint's cilium_calls. Therefore, inserting policy programs is considered
	// an 'attachment', just not through the typical bpf hooks.
	//
	// For example, a packet can enter to-container, jump into the bpf_host policy
	// program, which then jumps into the endpoint's policy program that are
	// installed by the loops below. If we allow packets to enter the endpoint's
	// bpf programs through its tc hook(s), _all_ this plumbing needs to be done
	// first, or we risk missing tail calls.
	if len(policyProgs) != 0 {
		if err := resolveAndInsertCalls(coll, policymap.PolicyCallMapName, policyProgs); err != nil {
			return nil, nil, fmt.Errorf("inserting policy programs: %w", err)
		}
	}

	if len(egressPolicyProgs) != 0 {
		if err := resolveAndInsertCalls(coll, policymap.PolicyEgressCallMapName, egressPolicyProgs); err != nil {
			return nil, nil, fmt.Errorf("inserting egress policy programs: %w", err)
		}
	}

	return coll, commit, nil
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

// enableForwarding puts the given link into the up state and enables IP forwarding.
func enableForwarding(sysctl sysctl.Sysctl, link netlink.Link) error {
	ifName := link.Attrs().Name

	if err := netlink.LinkSetUp(link); err != nil {
		log.WithError(err).WithField("device", ifName).Warn("Could not set up the link")
		return err
	}

	sysSettings := make([]tables.Sysctl, 0, 5)
	if option.Config.EnableIPv6 {
		sysSettings = append(sysSettings, tables.Sysctl{
			Name: fmt.Sprintf("net.ipv6.conf.%s.forwarding", ifName), Val: "1", IgnoreErr: false})
	}
	if option.Config.EnableIPv4 {
		sysSettings = append(sysSettings, []tables.Sysctl{
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

func setupVethPair(sysctl sysctl.Sysctl, name, peerName string) error {
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
	if err := enableForwarding(sysctl, veth); err != nil {
		return err
	}
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		return err
	}
	if err := enableForwarding(sysctl, peer); err != nil {
		return err
	}

	return nil
}

// setupBaseDevice decides which and what kind of interfaces should be set up as
// the first step of datapath initialization, then performs the setup (and
// creation, if needed) of those interfaces. It returns two links and an error.
// By default, it sets up the veth pair - cilium_host and cilium_net.
func setupBaseDevice(sysctl sysctl.Sysctl, mtu int) (netlink.Link, netlink.Link, error) {
	if err := setupVethPair(sysctl, defaults.HostDevice, defaults.SecondHostDevice); err != nil {
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
func setupTunnelDevice(sysctl sysctl.Sysctl, mode tunnel.Protocol, port uint16, mtu int) error {
	switch mode {
	case tunnel.Geneve:
		if err := setupGeneveDevice(sysctl, port, mtu); err != nil {
			return fmt.Errorf("setting up geneve device: %w", err)
		}
		if err := removeDevice(defaults.VxlanDevice); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.VxlanDevice, err)
		}

	case tunnel.VXLAN:
		if err := setupVxlanDevice(sysctl, port, mtu); err != nil {
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
func setupGeneveDevice(sysctl sysctl.Sysctl, dport uint16, mtu int) error {
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

	l, err := ensureDevice(sysctl, dev)
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
		if _, err := ensureDevice(sysctl, dev); err != nil {
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
func setupVxlanDevice(sysctl sysctl.Sysctl, port uint16, mtu int) error {
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

	l, err := ensureDevice(sysctl, dev)
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
		if _, err := ensureDevice(sysctl, dev); err != nil {
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
func setupIPIPDevices(sysctl sysctl.Sysctl, ipv4, ipv6 bool) error {
	// FlowBased sets IFLA_IPTUN_COLLECT_METADATA, the equivalent of 'ip link add
	// ... type ipip/ip6tnl external'. This is needed so bpf programs can use
	// bpf_skb_[gs]et_tunnel_key() on packets flowing through tunnels.

	if ipv4 {
		// Set up IPv4 tunnel device if requested.
		if _, err := ensureDevice(sysctl, &netlink.Iptun{
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
		if _, err := ensureDevice(sysctl, &netlink.Ip6tnl{
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
func ensureDevice(sysctl sysctl.Sysctl, attrs netlink.Link) (netlink.Link, error) {
	name := attrs.Attrs().Name

	// Reuse existing tunnel interface created by previous runs.
	l, err := netlink.LinkByName(name)
	if err != nil {
		if err := netlink.LinkAdd(attrs); err != nil {
			if errors.Is(err, unix.ENOTSUP) {
				err = fmt.Errorf("%w, maybe kernel module for %s is not available?", err, attrs.Type())
			}
			return nil, fmt.Errorf("creating device %s: %w", name, err)
		}

		// Fetch the link we've just created.
		l, err = netlink.LinkByName(name)
		if err != nil {
			return nil, fmt.Errorf("retrieving created device %s: %w", name, err)
		}
	}

	if err := enableForwarding(sysctl, l); err != nil {
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

// DeviceHasSKBProgramLoaded returns true if the given device has a tc(x) program
// attached.
//
// If checkEgress is true, returns true if there's both an ingress and
// egress program attached.
func DeviceHasSKBProgramLoaded(device string, checkEgress bool) (bool, error) {
	link, err := netlink.LinkByName(device)
	if err != nil {
		return false, fmt.Errorf("retrieving device %s: %w", device, err)
	}

	itcx, err := hasCiliumTCXLinks(link, ebpf.AttachTCXIngress)
	if err != nil {
		return false, err
	}
	itc, err := hasCiliumTCFilters(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return false, err
	}
	ink, err := hasCiliumNetkitLinks(link, ebpf.AttachNetkitPeer)
	if err != nil {
		return false, err
	}

	// Need ingress programs at minimum, bail out if these are already missing.
	if !itc && !itcx && !ink {
		return false, nil
	}

	if !checkEgress {
		return true, nil
	}

	etcx, err := hasCiliumTCXLinks(link, ebpf.AttachTCXEgress)
	if err != nil {
		return false, err
	}
	etc, err := hasCiliumTCFilters(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return false, err
	}
	enk, err := hasCiliumNetkitLinks(link, ebpf.AttachNetkitPrimary)
	if err != nil {
		return false, err
	}

	return etc || etcx || enk, nil
}
