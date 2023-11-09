// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/alignchecker"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/linux/ethtool"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/datapath/prefilter"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/identity"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/socketlb"
	"github.com/cilium/cilium/pkg/sysctl"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// firstInitialization is true when Reinitialize() is called for the first
// time. It can only be accessed when GetCompilationLock() is being held.
var firstInitialization = true

const (
	// netdevHeaderFileName is the name of the header file used for bpf_host.c and bpf_overlay.c.
	netdevHeaderFileName = "netdev_config.h"
	// preFilterHeaderFileName is the name of the header file used for bpf_xdp.c.
	preFilterHeaderFileName = "filter_config.h"
)

func (l *Loader) writeNetdevHeader(dir string, o datapath.BaseProgramOwner) error {
	headerPath := filepath.Join(dir, netdevHeaderFileName)
	log.WithField(logfields.Path, headerPath).Debug("writing configuration")

	f, err := os.Create(headerPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %s", headerPath, err)

	}
	defer f.Close()

	if err := l.templateCache.WriteNetdevConfig(f, o); err != nil {
		return err
	}
	return nil
}

func (l *Loader) writeNodeConfigHeader(o datapath.BaseProgramOwner) error {
	nodeConfigPath := option.Config.GetNodeConfigPath()
	f, err := os.Create(nodeConfigPath)
	if err != nil {
		return fmt.Errorf("failed to create node configuration file at %s: %w", nodeConfigPath, err)
	}
	defer f.Close()

	if err = l.templateCache.WriteNodeConfig(f, o.LocalConfig()); err != nil {
		return fmt.Errorf("failed to write node configuration file at %s: %w", nodeConfigPath, err)
	}
	return nil
}

// Must be called with option.Config.EnablePolicyMU locked.
func writePreFilterHeader(preFilter *prefilter.PreFilter, dir string) error {
	headerPath := filepath.Join(dir, preFilterHeaderFileName)
	log.WithField(logfields.Path, headerPath).Debug("writing configuration")

	f, err := os.Create(headerPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %s", headerPath, err)
	}
	defer f.Close()

	fw := bufio.NewWriter(f)
	fmt.Fprint(fw, "/*\n")
	fmt.Fprintf(fw, " * XDP devices: %s\n", strings.Join(option.Config.GetDevices(), " "))
	fmt.Fprintf(fw, " * XDP mode: %s\n", option.Config.NodePortAcceleration)
	fmt.Fprint(fw, " */\n\n")
	preFilter.WriteConfig(fw)
	return fw.Flush()
}

func addENIRules(sysSettings []sysctl.Setting, nodeAddressing datapath.NodeAddressing) ([]sysctl.Setting, error) {
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

	iface, err := route.NodeDeviceWithDefaultRoute(option.Config.EnableIPv4, option.Config.EnableIPv6)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface with default route: %w", err)
	}

	retSettings := append(sysSettings, sysctl.Setting{
		Name:      fmt.Sprintf("net.ipv4.conf.%s.rp_filter", iface.Attrs().Name),
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

	// Add rules for router (cilium_host).
	info := node.GetRouterInfo()
	cidrs := info.GetIPv4CIDRs()
	routerIP := net.IPNet{
		IP:   nodeAddressing.IPv4().Router(),
		Mask: net.CIDRMask(32, 32),
	}

	for _, cidr := range cidrs {
		if err = linuxrouting.SetupRules(&routerIP, &cidr, info.GetMac().String(), info.GetInterfaceNumber()); err != nil {
			return nil, fmt.Errorf("unable to install ip rule for cilium_host: %w", err)
		}
	}

	return retSettings, nil
}

// reinitializeIPSec is used to recompile and load encryption network programs.
func (l *Loader) reinitializeIPSec(ctx context.Context) error {
	if !option.Config.EnableIPSec {
		return nil
	}

	l.ipsecMu.Lock()
	defer l.ipsecMu.Unlock()

	interfaces := option.Config.EncryptInterface
	if option.Config.IPAM == ipamOption.IPAMENI {
		// IPAMENI mode supports multiple network facing interfaces that
		// will all need Encrypt logic applied in order to decrypt any
		// received encrypted packets. This logic will attach to all
		// !veth devices.
		interfaces = nil
		if links, err := netlink.LinkList(); err == nil {
			for _, link := range links {
				isVirtual, err := ethtool.IsVirtualDriver(link.Attrs().Name)
				if err == nil && !isVirtual {
					interfaces = append(interfaces, link.Attrs().Name)
				}
			}
		}
		option.Config.EncryptInterface = interfaces
	}

	// No interfaces is valid in tunnel disabled case
	if len(interfaces) != 0 {
		for _, iface := range interfaces {
			if err := connector.DisableRpFilter(iface); err != nil {
				log.WithError(err).WithField(logfields.Interface, iface).Warn("Rpfilter could not be disabled, node to node encryption may fail")
			}
		}

		if err := l.replaceNetworkDatapath(ctx, interfaces); err != nil {
			return fmt.Errorf("failed to load encryption program: %w", err)
		}
	}
	return nil
}

func (l *Loader) reinitializeOverlay(ctx context.Context, encapProto string) error {
	// encapProto can be one of option.[TunnelDisabled, TunnelVXLAN, TunnelGeneve]
	// if it is disabled, the overlay network programs don't have to be (re)initialized
	if encapProto == option.TunnelDisabled {
		return nil
	}

	iface := fmt.Sprintf("cilium_%s", encapProto)
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("failed to retrieve link for interface %s: %w", iface, err)
	}

	// gather compile options for bpf_overlay.c
	opts := []string{
		fmt.Sprintf("-DSECLABEL=%d", identity.ReservedIdentityWorld),
		fmt.Sprintf("-DNODE_MAC={.addr=%s}", mac.CArrayString(link.Attrs().HardwareAddr)),
		fmt.Sprintf("-DCALLS_MAP=cilium_calls_overlay_%d", identity.ReservedIdentityWorld),
	}
	if option.Config.EnableNodePort {
		opts = append(opts, "-DDISABLE_LOOPBACK_LB")
	}
	if option.Config.IsDualStack() {
		opts = append(opts, fmt.Sprintf("-DSECLABEL_IPV4=%d", identity.ReservedIdentityWorldIPv4))
		opts = append(opts, fmt.Sprintf("-DSECLABEL_IPV6=%d", identity.ReservedIdentityWorldIPv6))
	} else {
		opts = append(opts, fmt.Sprintf("-DSECLABEL_IPV4=%d", identity.ReservedIdentityWorld))
		opts = append(opts, fmt.Sprintf("-DSECLABEL_IPV6=%d", identity.ReservedIdentityWorld))
	}

	if err := l.replaceOverlayDatapath(ctx, opts, iface); err != nil {
		return fmt.Errorf("failed to load overlay programs: %w", err)
	}

	return nil
}

func (l *Loader) reinitializeXDPLocked(ctx context.Context, extraCArgs []string) error {
	maybeUnloadObsoleteXDPPrograms(option.Config.GetDevices(), option.Config.XDPMode, bpf.CiliumPath())
	if option.Config.XDPMode == option.XDPModeDisabled {
		return nil
	}
	for _, dev := range option.Config.GetDevices() {
		// When WG & encrypt-node are on, the devices include cilium_wg0 to attach bpf_host
		// so that NodePort's rev-{S,D}NAT translations happens for a reply from the remote node.
		// So We need to exclude cilium_wg0 not to attach the XDP program when XDP acceleration
		// is enabled, otherwise we will get "operation not supported" error.
		if dev == wgTypes.IfaceName {
			continue
		}
		if err := compileAndLoadXDPProg(ctx, dev, option.Config.XDPMode, extraCArgs); err != nil {
			return err
		}
	}
	return nil
}

// ReinitializeXDP (re-)configures the XDP datapath only. This includes recompilation
// and reinsertion of the object into the kernel as well as an atomic program replacement
// at the XDP hook. extraCArgs can be passed-in in order to alter BPF code defines.
func (l *Loader) ReinitializeXDP(ctx context.Context, o datapath.BaseProgramOwner, extraCArgs []string) error {
	o.GetCompilationLock().Lock()
	defer o.GetCompilationLock().Unlock()
	return l.reinitializeXDPLocked(ctx, extraCArgs)
}

// Reinitialize (re-)configures the base datapath configuration including global
// BPF programs, netfilter rule configuration and reserving routes in IPAM for
// locally detected prefixes. It may be run upon initial Cilium startup, after
// restore from a previous Cilium run, or during regular Cilium operation.
func (l *Loader) Reinitialize(ctx context.Context, o datapath.BaseProgramOwner, deviceMTU int, iptMgr datapath.IptablesManager, p datapath.Proxy) error {
	sysSettings := []sysctl.Setting{
		{Name: "net.core.bpf_jit_enable", Val: "1", IgnoreErr: true, Warn: "Unable to ensure that BPF JIT compilation is enabled. This can be ignored when Cilium is running inside non-host network namespace (e.g. with kind or minikube)"},
		{Name: "net.ipv4.conf.all.rp_filter", Val: "0", IgnoreErr: false},
		{Name: "net.ipv4.fib_multipath_use_neigh", Val: "1", IgnoreErr: true},
		{Name: "kernel.unprivileged_bpf_disabled", Val: "1", IgnoreErr: true},
		{Name: "kernel.timer_migration", Val: "0", IgnoreErr: true},
	}

	// Lock so that endpoints cannot be built while we are compile base programs.
	o.GetCompilationLock().Lock()
	defer o.GetCompilationLock().Unlock()
	defer func() { firstInitialization = false }()

	l.init(o.Datapath(), o.LocalConfig())

	encapProto := option.TunnelDisabled
	if option.Config.TunnelingEnabled() {
		encapProto = option.Config.TunnelProtocol
	}

	var nodeIPv4, nodeIPv6 net.IP
	if option.Config.EnableIPv4 {
		nodeIPv4 = node.GetInternalIPv4Router()
	}
	if option.Config.EnableIPv6 {
		nodeIPv6 = node.GetIPv6Router()
		// Docker <17.05 has an issue which causes IPv6 to be disabled in the initns for all
		// interface (https://github.com/docker/libnetwork/issues/1720)
		// Enable IPv6 for now
		sysSettings = append(sysSettings,
			sysctl.Setting{Name: "net.ipv6.conf.all.disable_ipv6", Val: "0", IgnoreErr: false})
	}

	// Datapath initialization
	hostDev1, _, err := SetupBaseDevice(deviceMTU)
	if err != nil {
		return fmt.Errorf("failed to setup base devices: %w", err)
	}

	if option.Config.EnableHealthDatapath {
		sysSettings = append(
			sysSettings,
			sysctl.Setting{
				Name: "net.core.fb_tunnels_only_for_init_net", Val: "2", IgnoreErr: true,
			},
		)
		if err := setupIPIPDevices(option.Config.IPv4Enabled(), option.Config.IPv6Enabled()); err != nil {
			return fmt.Errorf("unable to create ipip encapsulation devices for health datapath")
		}
	}

	if !option.Config.TunnelingEnabled() {
		if option.Config.EgressGatewayCommonEnabled() || option.Config.EnableHighScaleIPcache {
			// Tunnel is required for egress traffic under this config
			encapProto = option.Config.TunnelProtocol
		}
	}
	if !option.Config.TunnelingEnabled() &&
		option.Config.EnableNodePort &&
		option.Config.NodePortMode != option.NodePortModeSNAT &&
		option.Config.LoadBalancerDSRDispatch == option.DSRDispatchGeneve {
		encapProto = option.TunnelGeneve
	}

	if err := setupTunnelDevice(encapProto, option.Config.TunnelPort, deviceMTU); err != nil {
		return fmt.Errorf("failed to setup %s tunnel device: %w", encapProto, err)
	}

	if option.Config.IPAM == ipamOption.IPAMENI {
		var err error
		if sysSettings, err = addENIRules(sysSettings, o.Datapath().LocalNodeAddressing()); err != nil {
			return fmt.Errorf("unable to install ip rule for ENI multi-node NodePort: %w", err)
		}
	}

	// Any code that relies on sysctl settings being applied needs to be called after this.
	if err := sysctl.ApplySettings(sysSettings); err != nil {
		return err
	}

	// add internal ipv4 and ipv6 addresses to cilium_host
	if err := addHostDeviceAddr(hostDev1, nodeIPv4, nodeIPv6); err != nil {
		return fmt.Errorf("failed to add internal IP address to %s: %w", hostDev1.Attrs().Name, err)
	}

	if err := l.writeNodeConfigHeader(o); err != nil {
		log.WithError(err).Error("Unable to write node config header")
		return err
	}

	if err := l.writeNetdevHeader("./", o); err != nil {
		log.WithError(err).Warn("Unable to write netdev header")
		return err
	}

	if option.Config.EnableXDPPrefilter {
		scopedLog := log.WithField(logfields.Devices, option.Config.GetDevices())

		preFilter, err := prefilter.NewPreFilter()
		if err != nil {
			scopedLog.WithError(err).Warn("Unable to init prefilter")
			return err
		}

		if err := writePreFilterHeader(preFilter, "./"); err != nil {
			scopedLog.WithError(err).Warn("Unable to write prefilter header")
			return err
		}

		o.SetPrefilter(preFilter)
	}

	ctx, cancel := context.WithTimeout(ctx, defaults.ExecTimeout)
	defer cancel()

	if option.Config.EnableSocketLB {
		// compile bpf_sock.c and attach/detach progs for socketLB
		if err := CompileWithOptions(ctx, "bpf_sock.c", "bpf_sock.o", []string{"-DCALLS_MAP=cilium_calls_lb"}); err != nil {
			log.WithError(err).Fatal("failed to compile bpf_sock.c")
		}
		if err := socketlb.Enable(); err != nil {
			return err
		}
	} else {
		if err := socketlb.Disable(); err != nil {
			return err
		}
	}

	extraArgs := []string{"-Dcapture_enabled=0"}
	if err := l.reinitializeXDPLocked(ctx, extraArgs); err != nil {
		log.WithError(err).Fatal("Failed to compile XDP program")
	}

	// Compile alignchecker program
	if err := Compile(ctx, "bpf_alignchecker.c", defaults.AlignCheckerName); err != nil {
		log.WithError(err).Fatal("alignchecker compile failed")
	}
	// Validate alignments of C and Go equivalent structs
	if err := alignchecker.CheckStructAlignments(defaults.AlignCheckerName); err != nil {
		log.WithError(err).Fatal("C and Go structs alignment check failed")
	}

	if option.Config.EnableIPSec {
		if err := compileNetwork(ctx); err != nil {
			log.WithError(err).Fatal("failed to compile encryption programs")
		}

		if err := l.reinitializeIPSec(ctx); err != nil {
			return err
		}

		if firstInitialization {
			// Start a background worker to reinitialize IPsec if links change.
			l.reloadIPSecOnLinkChanges()
		}
	}

	if err := l.reinitializeOverlay(ctx, encapProto); err != nil {
		return err
	}

	if err := o.Datapath().Node().NodeConfigurationChanged(*o.LocalConfig()); err != nil {
		return err
	}

	if err := iptMgr.InstallRules(ctx, defaults.HostDevice, firstInitialization, option.Config.InstallIptRules); err != nil {
		return err
	}

	// Reinstall proxy rules for any running proxies if needed
	if option.Config.EnableL7Proxy {
		if err := p.ReinstallRoutingRules(); err != nil {
			return err
		}

		if err := p.ReinstallIPTablesRules(ctx); err != nil {
			return err
		}
	}

	return nil
}
