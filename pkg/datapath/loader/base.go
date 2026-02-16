// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/alignchecker"
	"github.com/cilium/cilium/pkg/datapath/linux/ethtool"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/socketlb"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

const (
	// netdevHeaderFileName is the name of the header file used for bpf_host.c and bpf_overlay.c.
	netdevHeaderFileName = "netdev_config.h"
	// preFilterHeaderFileName is the name of the header file used for bpf_xdp.c.
	preFilterHeaderFileName = "filter_config.h"
)

func (l *loader) writeNetdevHeader(dir string) error {
	headerPath := filepath.Join(dir, netdevHeaderFileName)
	l.logger.Debug("writing configuration", logfields.Path, headerPath)

	f, err := os.Create(headerPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %w", headerPath, err)
	}
	defer f.Close()

	if err := l.templateCache.WriteNetdevConfig(f, option.Config.Opts); err != nil {
		return err
	}
	return nil
}

func (l *loader) writeNodeConfigHeader(cfg *datapath.LocalNodeConfiguration) error {
	nodeConfigPath := option.Config.GetNodeConfigPath()
	f, err := os.Create(nodeConfigPath)
	if err != nil {
		return fmt.Errorf("failed to create node configuration file at %s: %w", nodeConfigPath, err)
	}
	defer f.Close()

	if err = l.templateCache.WriteNodeConfig(f, cfg); err != nil {
		return fmt.Errorf("failed to write node configuration file at %s: %w", nodeConfigPath, err)
	}
	return nil
}

// Must be called with option.Config.EnablePolicyMU locked.
func writePreFilterHeader(logger *slog.Logger, preFilter datapath.PreFilter, dir string, devices []string) error {
	headerPath := filepath.Join(dir, preFilterHeaderFileName)
	logger.Debug("writing configuration", logfields.Path, headerPath)

	f, err := os.Create(headerPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %w", headerPath, err)
	}
	defer f.Close()

	fw := bufio.NewWriter(f)
	fmt.Fprint(fw, "/*\n")
	fmt.Fprintf(fw, " * XDP devices: %s\n", strings.Join(devices, " "))
	fmt.Fprintf(fw, " * XDP mode: %s\n", option.Config.NodePortAcceleration)
	fmt.Fprint(fw, " */\n\n")
	preFilter.WriteConfig(fw)
	return fw.Flush()
}

func addENIRules(logger *slog.Logger, sysSettings []tables.Sysctl) ([]tables.Sysctl, error) {
	// AWS ENI mode requires symmetric routing, see
	// iptables.addCiliumENIRules().
	// The default AWS daemonset installs the following rules that are used
	// for NodePort traffic between nodes:
	//
	// # sysctl -w net.ipv4.conf.eth0.rp_filter=2
	// # iptables -t mangle -A PREROUTING -i eth0 -m comment --comment "AWS, primary ENI" -m addrtype --dst-type LOCAL --limit-iface-in -j CONNMARK --set-xmark 0x80/0x80
	// # iptables -t mangle -A PREROUTING -i eni+ -m comment --comment "AWS, primary ENI" -j CONNMARK --restore-mark --nfmask 0x80 --ctmask 0x80
	// # ip rule add fwmark 0x80/0x80 lookup main
	//
	// It marks packets coming from another node through eth0, and restores
	// the mark on the return path to force a lookup into the main routing
	// table. Without these rules, the "ip rules" set by the cilium-cni
	// plugin tell the host to lookup into the table related to the VPC for
	// which the CIDR used by the endpoint has been configured.
	//
	// We want to reproduce equivalent rules to ensure correct routing.
	if !option.Config.EnableIPv4 {
		return sysSettings, nil
	}

	iface, err := route.NodeDeviceWithDefaultRoute(logger, option.Config.EnableIPv4, option.Config.EnableIPv6)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface with default route: %w", err)
	}

	retSettings := append(sysSettings, tables.Sysctl{
		Name:      []string{"net", "ipv4", "conf", iface.Attrs().Name, "rp_filter"},
		Val:       "2",
		IgnoreErr: false,
	})
	if err := route.ReplaceRule(route.Rule{
		Priority: linux_defaults.RulePriorityNodeport,
		Mark:     linux_defaults.MarkMultinodeNodeport,
		Mask:     linux_defaults.MaskMultinodeNodeport,
		Table:    route.MainTable,
		Protocol: linux_defaults.RTProto,
	}); err != nil {
		return nil, fmt.Errorf("unable to install ip rule for ENI multi-node NodePort: %w", err)
	}

	return retSettings, nil
}

func cleanIngressQdisc(logger *slog.Logger, devices []string) error {
	for _, iface := range devices {
		link, err := safenetlink.LinkByName(iface)
		if err != nil {
			return fmt.Errorf("failed to retrieve link %s by name: %w", iface, err)
		}
		qdiscs, err := safenetlink.QdiscList(link)
		if err != nil {
			return fmt.Errorf("failed to retrieve qdisc list of link %s: %w", iface, err)
		}
		for _, q := range qdiscs {
			if q.Type() != "ingress" {
				continue
			}
			err = netlink.QdiscDel(q)
			if err != nil {
				return fmt.Errorf("failed to delete ingress qdisc of link %s: %w", iface, err)
			} else {
				logger.Info("Removed prior present ingress qdisc from device so that Cilium's datapath can be loaded", logfields.Device, iface)
			}
		}
	}
	return nil
}

// cleanCallsMaps is used to remove any pinned map matching mapNamePattern from bpf.TCGlobalsPath().
func cleanCallsMaps(mapNamePattern string) error {
	matches, err := filepath.Glob(filepath.Join(bpf.TCGlobalsPath(), mapNamePattern))
	if err != nil {
		return fmt.Errorf("failed to list maps with mapNamePattern %s: %w", mapNamePattern, err)
	}

	for _, match := range matches {
		err = errors.Join(err, os.RemoveAll(match))
	}

	return err
}

// reinitializeEncryption is used to recompile and load encryption network programs.
func (l *loader) reinitializeEncryption(ctx context.Context, lnc *datapath.LocalNodeConfiguration) error {
	// We need to take care not to load bpf_network and bpf_host onto the same
	// device. If devices are required, we load bpf_host and hence don't need
	// the code below, specific to EncryptInterface. Specifically, we will load
	// bpf_host code in reloadHostDatapath onto the physical devices as selected
	// by configuration.
	if !lnc.EnableIPSec || option.Config.AreDevicesRequired(lnc.KPRConfig, lnc.EnableWireguard, lnc.EnableIPSec) {
		os.RemoveAll(bpfStateDeviceDir(networkConfig))

		return nil
	}

	l.ipsecMu.Lock()
	defer l.ipsecMu.Unlock()

	var attach []netlink.Link
	if option.Config.IPAM == ipamOption.IPAMENI {
		// IPAMENI mode supports multiple network facing interfaces that
		// will all need Encrypt logic applied in order to decrypt any
		// received encrypted packets. This logic will attach to all
		// !veth devices.
		//
		// Regenerate the list of interfaces to attach to on every call.
		links, err := safenetlink.LinkList()
		if err != nil {
			return err
		}

		// Always attach to all physical devices in ENI mode.
		attach = physicalDevs(links)
		option.Config.UnsafeDaemonConfigOption.EncryptInterface = linkNames(attach)
	} else {
		// In other modes, attach only to the interfaces explicitly specified by the
		// user. Resolve links by name.
		for _, iface := range option.Config.UnsafeDaemonConfigOption.EncryptInterface {
			link, err := safenetlink.LinkByName(iface)
			if err != nil {
				return fmt.Errorf("retrieving device %s: %w", iface, err)
			}
			attach = append(attach, link)
		}
	}

	// No interfaces is valid in tunnel disabled case
	if len(attach) == 0 {
		return nil
	}

	if err := replaceEncryptionDatapath(ctx, l.logger, lnc, attach); err != nil {
		return fmt.Errorf("failed to replace encryption datapath: %w", err)
	}

	return nil
}

func physicalDevs(links []netlink.Link) []netlink.Link {
	var phys []netlink.Link
	for _, link := range links {
		isVirtual, err := ethtool.IsVirtualDriver(link.Attrs().Name)
		if err == nil && !isVirtual {
			phys = append(phys, link)
		}
	}
	return phys
}

func linkNames(links []netlink.Link) []string {
	var names []string
	for _, link := range links {
		names = append(names, link.Attrs().Name)
	}
	return names
}

func reinitializeOverlay(ctx context.Context, logger *slog.Logger, lnc *datapath.LocalNodeConfiguration, tunnelConfig tunnel.Config) error {
	// tunnelConfig.EncapProtocol() can be one of tunnel.[Disabled, VXLAN, Geneve]
	// if it is disabled, the overlay network programs don't have to be (re)initialized
	if tunnelConfig.EncapProtocol() == tunnel.Disabled {
		cleanCallsMaps("cilium_calls_overlay*")

		os.RemoveAll(bpfStateDeviceDir(defaults.VxlanDevice))
		os.RemoveAll(bpfStateDeviceDir(defaults.GeneveDevice))

		return nil
	}

	iface := tunnelConfig.DeviceName()
	link, err := safenetlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("failed to retrieve link for interface %s: %w", iface, err)
	}

	if err := replaceOverlayDatapath(ctx, logger, lnc, link); err != nil {
		return fmt.Errorf("failed to load overlay programs: %w", err)
	}

	return nil
}

func reinitializeWireguard(ctx context.Context, logger *slog.Logger, lnc *datapath.LocalNodeConfiguration) (err error) {
	if !lnc.EnableWireguard {
		cleanCallsMaps("cilium_calls_wireguard*")

		os.RemoveAll(bpfStateDeviceDir(wgTypes.IfaceName))

		return
	}

	link, err := safenetlink.LinkByName(wgTypes.IfaceName)
	if err != nil {
		return fmt.Errorf("failed to retrieve link for interface %s: %w", wgTypes.IfaceName, err)
	}

	if err := replaceWireguardDatapath(ctx, logger, lnc, link); err != nil {
		return fmt.Errorf("failed to load wireguard programs: %w", err)
	}
	return
}

func reinitializeXDPLocked(ctx context.Context, logger *slog.Logger, lnc *datapath.LocalNodeConfiguration, devices []string) error {
	xdpConfig := lnc.XDPConfig
	maybeUnloadObsoleteXDPPrograms(logger, devices, xdpConfig.Mode(), bpf.CiliumPath())
	if xdpConfig.Disabled() {
		return nil
	}
	for _, dev := range devices {
		// When WG & encrypt-node are on, the devices include cilium_wg0 to attach cil_from_wireguard
		// so that NodePort's rev-{S,D}NAT translations happens for a reply from the remote node.
		// So We need to exclude cilium_wg0 not to attach the XDP program when XDP acceleration
		// is enabled, otherwise we will get "operation not supported" error.
		if dev == wgTypes.IfaceName {
			continue
		}

		if err := compileAndLoadXDPProg(ctx, logger, lnc, dev, xdpConfig.Mode()); err != nil {
			if option.Config.NodePortAcceleration == option.XDPModeBestEffort {
				logger.Info("Failed to attach XDP program, ignoring due to best-effort mode",
					logfields.Error, err,
					logfields.Device, dev,
				)
			} else {
				return fmt.Errorf("attaching XDP program to interface %s: %w", dev, err)
			}
		}
	}

	return nil
}

func (l *loader) ReinitializeHostDev(ctx context.Context, mtu int) error {
	_, _, err := setupBaseDevice(l.logger, l.sysctl, mtu)
	if err != nil {
		return fmt.Errorf("failed to setup base devices: %w", err)
	}

	return nil
}

// Reinitialize (re-)configures the base datapath configuration including global
// BPF programs, netfilter rule configuration and reserving routes in IPAM for
// locally detected prefixes. It may be run upon initial Cilium startup, after
// restore from a previous Cilium run, or during regular Cilium operation.
func (l *loader) Reinitialize(ctx context.Context, lnc *datapath.LocalNodeConfiguration, tunnelConfig tunnel.Config, iptMgr datapath.IptablesManager, p datapath.Proxy, bigtcp datapath.BigTCPConfiguration) error {
	sysSettings := []tables.Sysctl{
		{Name: []string{"net", "core", "bpf_jit_enable"}, Val: "1", IgnoreErr: true, Warn: "Unable to ensure that BPF JIT compilation is enabled. This can be ignored when Cilium is running inside non-host network namespace (e.g. with kind or minikube)"},
		{Name: []string{"net", "ipv4", "conf", "all", "rp_filter"}, Val: "0", IgnoreErr: false},
		{Name: []string{"net", "ipv4", "fib_multipath_use_neigh"}, Val: "1", IgnoreErr: true},
		{Name: []string{"kernel", "unprivileged_bpf_disabled"}, Val: "1", IgnoreErr: true},
		{Name: []string{"kernel", "timer_migration"}, Val: "0", IgnoreErr: true},
	}

	// Lock so that endpoints cannot be built while we are compile base programs.
	l.compilationLock.Lock()
	defer l.compilationLock.Unlock()

	// Startup relies on not returning an error here, maybe something we
	// can fix in the future.
	_ = l.templateCache.UpdateDatapathHash(lnc)

	var internalIPv4, internalIPv6 net.IP
	if option.Config.EnableIPv4 {
		internalIPv4 = net.IP(lnc.CiliumInternalIPv4.AsSlice())
	}
	if option.Config.EnableIPv6 {
		internalIPv6 = net.IP(lnc.CiliumInternalIPv6.AsSlice())
		// Docker <17.05 has an issue which causes IPv6 to be disabled in the initns for all
		// interface (https://github.com/docker/libnetwork/issues/1720)
		// Enable IPv6 for now
		sysSettings = append(sysSettings,
			tables.Sysctl{Name: []string{"net", "ipv6", "conf", "all", "disable_ipv6"}, Val: "0", IgnoreErr: false})
	}

	// BPF file system setup.
	if err := bpf.MkdirBPF(bpf.TCGlobalsPath()); err != nil {
		return fmt.Errorf("failed to create bpffs directory: %w", err)
	}

	// Datapath initialization
	hostDev1, _, err := setupBaseDevice(l.logger, l.sysctl, lnc.DeviceMTU)
	if err != nil {
		return fmt.Errorf("failed to setup base devices: %w", err)
	}

	if option.Config.UnsafeDaemonConfigOption.EnableIPIPDevices {
		// This setting needs to be applied before creating the IPIP devices.
		sysIPIP := []tables.Sysctl{
			{Name: []string{"net", "core", "fb_tunnels_only_for_init_net"}, Val: "2", IgnoreErr: true},
		}
		if err := l.sysctl.ApplySettings(sysIPIP); err != nil {
			return err
		}
		if err := setupIPIPDevices(l.logger, l.sysctl, option.Config.IPv4Enabled(), option.Config.IPv6Enabled(), lnc.DeviceMTU); err != nil {
			return fmt.Errorf("unable to create ipip devices: %w", err)
		}
	}

	if err := setupTunnelDevice(l.logger, l.sysctl, tunnelConfig.EncapProtocol(), tunnelConfig.Port(),
		tunnelConfig.SrcPortLow(), tunnelConfig.SrcPortHigh(), lnc.DeviceMTU, bigtcp); err != nil {
		return fmt.Errorf("failed to setup %s tunnel device: %w", tunnelConfig.EncapProtocol(), err)
	}

	if option.Config.IPAM == ipamOption.IPAMENI {
		var err error
		if sysSettings, err = addENIRules(l.logger, sysSettings); err != nil {
			return fmt.Errorf("unable to install ip rule for ENI multi-node NodePort: %w", err)
		}
	}

	// Any code that relies on sysctl settings being applied needs to be called after this.
	if err := l.sysctl.ApplySettings(sysSettings); err != nil {
		return err
	}

	// add internal ipv4 and ipv6 addresses to cilium_host
	if err := addHostDeviceAddr(hostDev1, internalIPv4, internalIPv6); err != nil {
		return fmt.Errorf("failed to add internal IP address to %s: %w", hostDev1.Attrs().Name, err)
	}

	devices := lnc.DeviceNames()
	if err := cleanIngressQdisc(l.logger, devices); err != nil {
		l.logger.Warn("Unable to clean up ingress qdiscs", logfields.Error, err)
		return err
	}

	if err := l.writeNodeConfigHeader(lnc); err != nil {
		l.logger.Error("Unable to write node config header", logfields.Error, err)
		return err
	}

	if err := l.writeNetdevHeader("./"); err != nil {
		l.logger.Warn("Unable to write netdev header", logfields.Error, err)
		return err
	}

	if option.Config.EnableXDPPrefilter {
		if err := writePreFilterHeader(l.logger, l.prefilter, "./", devices); err != nil {
			l.logger.Warn("Unable to write prefilter header",
				logfields.Error, err,
				logfields.Devices, devices,
			)
			return err
		}
	}

	ctx, cancel := context.WithTimeout(ctx, defaults.ExecTimeout)
	defer cancel()

	if lnc.KPRConfig.EnableSocketLB {
		// compile bpf_sock.c and attach/detach progs for socketLB
		if err := compileWithOptions(ctx, l.logger, "bpf_sock.c", "bpf_sock.o", nil); err != nil {
			logging.Fatal(l.logger, "failed to compile bpf_sock.c", logfields.Error, err)
		}
		if err := socketlb.Enable(l.logger, l.sysctl, lnc); err != nil {
			return err
		}
	} else {
		if err := socketlb.Disable(l.logger); err != nil {
			return err
		}
	}

	if err := reinitializeXDPLocked(ctx, l.logger, lnc, devices); err != nil {
		logging.Fatal(l.logger, "Failed to compile XDP program", logfields.Error, err)
	}

	// Compile alignchecker program
	if err := compileDefault(ctx, l.logger, "bpf_alignchecker.c", defaults.AlignCheckerName); err != nil {
		logging.Fatal(l.logger, "alignchecker compile failed", logfields.Error, err)
	}
	// Validate alignments of C and Go equivalent structs
	if err := alignchecker.CheckStructAlignments(defaults.AlignCheckerName); err != nil {
		logging.Fatal(l.logger, "C and Go structs alignment check failed", logfields.Error, err)
	}

	if err := l.reinitializeEncryption(ctx, lnc); err != nil {
		return err
	}

	if err := reinitializeWireguard(ctx, l.logger, lnc); err != nil {
		return err
	}

	if err := reinitializeOverlay(ctx, l.logger, lnc, tunnelConfig); err != nil {
		return err
	}

	if err := l.nodeConfigNotifier.Notify(*lnc); err != nil {
		return err
	}

	// Reinstall proxy rules for any running proxies if needed
	if err := p.ReinstallRoutingRules(ctx, lnc.RouteMTU, lnc.EnableIPSec, lnc.EnableWireguard); err != nil {
		return err
	}

	return nil
}
