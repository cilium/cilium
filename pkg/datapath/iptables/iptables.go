// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/mattn/go-shellwords"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/modules"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn/proxy/ipfamily"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/versioncheck"
)

const (
	oldCiliumPrefix       = "OLD_"
	ciliumInputChain      = "CILIUM_INPUT"
	ciliumOutputChain     = "CILIUM_OUTPUT"
	ciliumOutputRawChain  = "CILIUM_OUTPUT_raw"
	ciliumPostNatChain    = "CILIUM_POST_nat"
	ciliumOutputNatChain  = "CILIUM_OUTPUT_nat"
	ciliumPreNatChain     = "CILIUM_PRE_nat"
	ciliumPostMangleChain = "CILIUM_POST_mangle"
	ciliumPreMangleChain  = "CILIUM_PRE_mangle"
	ciliumPreRawChain     = "CILIUM_PRE_raw"
	ciliumForwardChain    = "CILIUM_FORWARD"
	feederDescription     = "cilium-feeder:"
	xfrmDescription       = "cilium-xfrm-notrack:"
)

// Minimum iptables versions supporting the -w and -w<seconds> flags
var (
	isWaitMinVersion        = versioncheck.MustCompile(">=1.4.20")
	isWaitSecondsMinVersion = versioncheck.MustCompile(">=1.4.22")
	noTrackPorts            = func(port uint16) []*lb.L4Addr {
		return []*lb.L4Addr{
			{
				Protocol: lb.TCP,
				Port:     port,
			},
			{
				Protocol: lb.UDP,
				Port:     port,
			},
		}
	}
)

const (
	waitString = "-w"
)

type runnable interface {
	runProgOutput(args []string) (string, error)
	runProg(args []string) error
}

type iptablesInterface interface {
	runnable

	getProg() string
	getIpset() string
}

type ipt struct {
	prog     string
	ipset    string
	waitArgs []string
}

func (ipt *ipt) initArgs(ctx context.Context, waitSeconds int) {
	v, err := ipt.getVersion(ctx)
	if err == nil {
		switch {
		case isWaitSecondsMinVersion(v):
			ipt.waitArgs = []string{waitString, fmt.Sprintf("%d", waitSeconds)}
		case isWaitMinVersion(v):
			ipt.waitArgs = []string{waitString}
		}
	}
}

// package name is iptables so we use ip4tables internally for "iptables"
var (
	ip4tables = &ipt{prog: "iptables", ipset: ipset.CiliumNodeIPSetV4}
	ip6tables = &ipt{prog: "ip6tables", ipset: ipset.CiliumNodeIPSetV6}
)

func (ipt *ipt) getProg() string {
	return ipt.prog
}

func (ipt *ipt) getIpset() string {
	return ipt.ipset
}

func (ipt *ipt) getVersion(ctx context.Context) (semver.Version, error) {
	b, err := exec.CommandContext(ctx, ipt.prog, "--version").CombinedOutput(log, false)
	if err != nil {
		return semver.Version{}, err
	}
	v := regexp.MustCompile(`v([0-9]+(\.[0-9]+)+)`)
	vString := v.FindStringSubmatch(string(b))
	if vString == nil {
		return semver.Version{}, fmt.Errorf("no iptables version found in string: %s", string(b))
	}
	return versioncheck.Version(vString[1])
}

func (ipt *ipt) runProgOutput(args []string) (string, error) {
	fullCommand := fmt.Sprintf("%s %s", ipt.getProg(), strings.Join(args, " "))

	log.Debugf("Running '%s' command", fullCommand)

	// Add wait argument to deal with concurrent calls that would fail otherwise
	iptArgs := make([]string, 0, len(ipt.waitArgs)+len(args))
	iptArgs = append(iptArgs, ipt.waitArgs...)
	iptArgs = append(iptArgs, args...)
	out, err := exec.WithTimeout(defaults.ExecTimeout, ipt.prog, iptArgs...).Output(log, false)

	if err != nil {
		return "", fmt.Errorf("unable to run '%s' iptables command: %w", fullCommand, err)
	}
	return string(out), nil
}

func (ipt *ipt) runProg(args []string) error {
	_, err := ipt.runProgOutput(args)
	return err
}

func reverseRule(rule string) ([]string, error) {
	if strings.HasPrefix(rule, "-A") {
		// From: -A POSTROUTING -m comment [...]
		// To:   -D POSTROUTING -m comment [...]
		return shellwords.Parse(strings.Replace(rule, "-A", "-D", 1))
	}

	if strings.HasPrefix(rule, "-I") {
		// From: -I POSTROUTING -m comment [...]
		// To:   -D POSTROUTING -m comment [...]
		return shellwords.Parse(strings.Replace(rule, "-I", "-D", 1))
	}

	return []string{}, nil
}

func ruleReferencesDisabledChain(disableIptablesFeederRules []string, rule string) (bool, string) {
	for _, disabledChain := range disableIptablesFeederRules {
		if strings.Contains(rule, " "+strings.ToUpper(disabledChain)+" ") {
			return true, disabledChain
		}
	}

	return false, ""
}

func isDisabledChain(disableIptablesFeederRules []string, chain string) bool {
	for _, disabledChain := range disableIptablesFeederRules {
		if strings.EqualFold(chain, disabledChain) {
			return true
		}
	}

	return false
}

func (m *Manager) removeCiliumRules(table string, prog runnable, match string) error {
	rules, err := prog.runProgOutput([]string{"-t", table, "-S"})
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(strings.NewReader(rules))
	for scanner.Scan() {
		rule := scanner.Text()

		// All rules installed by cilium either belong to a chain with
		// the name CILIUM_ or call a chain with the name CILIUM_:
		// -A CILIUM_FORWARD -o cilium_host -m comment --comment "cilium: any->cluster on cilium_host forward accept" -j ACCEPT
		// -A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST" -j CILIUM_POST
		if !strings.Contains(rule, match) {
			continue
		}

		// Temporary fix while Iptables is upgraded to >= 1.8.5
		// (See GH-20884).
		//
		// The version currently shipped with Cilium (1.8.4) does not
		// support the deletion of NOTRACK rules, so we will just ignore
		// them here and let the agent remove them when it deletes the
		// entire chain.
		if strings.Contains(rule, "-j NOTRACK") {
			continue
		}

		// do not remove feeder for chains that are set to be disabled
		// ie catch the beginning of the rule like -A POSTROUTING to match it against
		// disabled chains
		if skip, disabledChain := ruleReferencesDisabledChain(m.cfg.DisableIptablesFeederRules, rule); skip {
			log.WithField(logfields.Chain, disabledChain).Info("Skipping the removal of feeder chain")
			continue
		}

		reversedRule, err := reverseRule(rule)
		if err != nil {
			log.WithError(err).WithField(logfields.Object, rule).Warnf("Unable to parse %s rule into slice. Leaving rule behind.", prog)
			continue
		}

		if len(reversedRule) > 0 {
			deleteRule := append([]string{"-t", table}, reversedRule...)
			if err := prog.runProg(deleteRule); err != nil {
				return err
			}
		}
	}

	return nil
}

// Manager manages the iptables-related configuration for Cilium.
type Manager struct {
	// This lock ensures there are no concurrent executions of the doInstallRules() and
	// GetProxyPort() methods.
	lock lock.Mutex

	logger     logrus.FieldLogger
	modulesMgr *modules.Manager
	sysctl     sysctl.Sysctl

	cfg       Config
	sharedCfg SharedConfig

	// anything that can trigger a reconciliation
	reconcilerParams reconcilerParams

	haveIp6tables        bool
	haveSocketMatch      bool
	haveBPFSocketAssign  bool
	ipEarlyDemuxDisabled bool
	cniConfigManager     cni.CNIConfigManager
}

type reconcilerParams struct {
	localNodeStore *node.LocalNodeStore
	db             *statedb.DB
	devices        statedb.Table[*tables.Device]
	proxies        chan reconciliationRequest[proxyInfo]
	addNoTrackPod  chan reconciliationRequest[noTrackPodInfo]
	delNoTrackPod  chan reconciliationRequest[noTrackPodInfo]
}

type params struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle cell.Lifecycle

	ModulesMgr       *modules.Manager
	Sysctl           sysctl.Sysctl
	CNIConfigManager cni.CNIConfigManager
	LocalNodeStore   *node.LocalNodeStore

	Cfg       Config
	SharedCfg SharedConfig

	JobGroup job.Group
	DB       *statedb.DB
	Devices  statedb.Table[*tables.Device]
}

func newIptablesManager(p params) *Manager {
	iptMgr := &Manager{
		logger:     p.Logger,
		modulesMgr: p.ModulesMgr,
		sysctl:     p.Sysctl,
		cfg:        p.Cfg,
		sharedCfg:  p.SharedCfg,
		reconcilerParams: reconcilerParams{
			localNodeStore: p.LocalNodeStore,
			db:             p.DB,
			devices:        p.Devices,
			proxies:        make(chan reconciliationRequest[proxyInfo]),
			addNoTrackPod:  make(chan reconciliationRequest[noTrackPodInfo]),
			delNoTrackPod:  make(chan reconciliationRequest[noTrackPodInfo]),
		},
		haveIp6tables:    true,
		cniConfigManager: p.CNIConfigManager,
	}

	// init iptables/ip6tables wait arguments before using them in the reconciler or in the manager (e.g: GetProxyPorts)
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			ip4tables.initArgs(ctx, int(p.Cfg.IPTablesLockTimeout/time.Second))
			if p.SharedCfg.EnableIPv6 {
				ip6tables.initArgs(ctx, int(p.Cfg.IPTablesLockTimeout/time.Second))
			}
			return nil
		},
	})

	p.Lifecycle.Append(iptMgr)

	p.JobGroup.Add(
		job.OneShot("iptables-reconciliation-loop", func(ctx context.Context, health cell.Health) error {
			return reconciliationLoop(
				ctx, p.Logger, health,
				iptMgr.sharedCfg.InstallIptRules, &iptMgr.reconcilerParams,
				iptMgr.doInstallRules,
				iptMgr.doInstallProxyRules,
				iptMgr.installNoTrackRules,
				iptMgr.removeNoTrackRules,
			)
		}),
	)

	return iptMgr
}

// Start initializes the iptables manager and checks for iptables kernel modules availability.
func (m *Manager) Start(ctx cell.HookContext) error {
	if os.Getenv("CILIUM_PREPEND_IPTABLES_CHAIN") != "" {
		m.logger.Warning("CILIUM_PREPEND_IPTABLES_CHAIN env var has been deprecated. Please use 'CILIUM_PREPEND_IPTABLES_CHAINS' " +
			"env var or '--prepend-iptables-chains' command line flag instead")
	}

	if err := enableIPForwarding(m.sysctl, m.sharedCfg.EnableIPv6); err != nil {
		m.logger.WithError(err).Warning("enabling IP forwarding via sysctl failed")
	}

	if m.sharedCfg.EnableIPSec && m.sharedCfg.EnableL7Proxy {
		m.disableIPEarlyDemux()
	}

	if err := m.modulesMgr.FindOrLoadModules(
		"ip_tables", "iptable_nat", "iptable_mangle", "iptable_raw", "iptable_filter",
	); err != nil {
		m.logger.WithError(err).Warning(
			"iptables modules could not be initialized. It probably means that iptables is not available on this system")
	}

	if err := m.modulesMgr.FindOrLoadModules(
		"ip6_tables", "ip6table_mangle", "ip6table_raw", "ip6table_filter",
	); err != nil {
		if m.sharedCfg.EnableIPv6 {
			return fmt.Errorf(
				"IPv6 is enabled and ip6tables modules initialization failed: %w "+
					"(try disabling IPv6 in Cilium or loading ip6_tables, ip6table_mangle, ip6table_raw and ip6table_filter kernel modules)", err)
		}
		m.logger.WithError(err).Debug(
			"ip6tables kernel modules could not be loaded, so IPv6 cannot be used")
		m.haveIp6tables = false
	} else {
		ipv6Disabled, err := os.ReadFile("/sys/module/ipv6/parameters/disable")
		if err != nil {
			if m.sharedCfg.EnableIPv6 {
				return fmt.Errorf(
					"IPv6 is enabled but IPv6 kernel support probing failed with: %w", err)
			}
			m.logger.WithError(err).Warning(
				"Unable to read /sys/module/ipv6/parameters/disable, disabling IPv6 iptables support")
			m.haveIp6tables = false
		} else if strings.TrimSuffix(string(ipv6Disabled), "\n") == "1" {
			m.logger.Debug(
				"Kernel does not support IPv6, disabling IPv6 iptables support")
			m.haveIp6tables = false
		}
	}

	if err := m.modulesMgr.FindOrLoadModules("xt_socket"); err != nil {
		if !m.sharedCfg.TunnelingEnabled {
			// xt_socket module is needed to circumvent an explicit drop in ip_forward()
			// logic for packets for which a local socket is found by ip early
			// demux. xt_socket performs a local socket match and sets an skb mark on
			// match, which will divert the packet to the local stack using our policy
			// routing rule, thus avoiding being processed by ip_forward() at all.
			//
			// If xt_socket module does not exist we can disable ip early demux to to
			// avoid the explicit drop in ip_forward(). This is not needed in tunneling
			// modes, as then we'll set the skb mark in the bpf logic before the policy
			// routing stage so that the packet is routed locally instead of being
			// forwarded by ip_forward().
			//
			// We would not need the xt_socket at all if the datapath universally would
			// set the "to proxy" skb mark bits on before the packet hits policy routing
			// stage. Currently this is not true for endpoint routing modes.
			m.logger.WithError(err).Warning("xt_socket kernel module could not be loaded")

			if m.sharedCfg.EnableXTSocketFallback {
				m.disableIPEarlyDemux()
			}
		}
	} else {
		m.haveSocketMatch = true
	}
	m.haveBPFSocketAssign = m.sharedCfg.EnableBPFTProxy

	return nil
}

func (m *Manager) Stop(ctx cell.HookContext) error {
	close(m.reconcilerParams.proxies)
	close(m.reconcilerParams.addNoTrackPod)
	close(m.reconcilerParams.delNoTrackPod)
	return nil
}

func (m *Manager) disableIPEarlyDemux() {
	if m.ipEarlyDemuxDisabled {
		return
	}

	disabled := m.sysctl.Disable("net.ipv4.ip_early_demux") == nil
	if disabled {
		m.ipEarlyDemuxDisabled = true
		m.logger.Info("Disabled ip_early_demux to allow proxy redirection with original source/destination address without xt_socket support also in non-tunneled datapath modes.")
	} else {
		m.logger.Warning("Could not disable ip_early_demux, traffic redirected due to an HTTP policy or visibility may be dropped unexpectedly")
	}
}

// SupportsOriginalSourceAddr tells if an L7 proxy can use POD's original source address and port in
// the upstream connection to allow the destination to properly derive the source security ID from
// the source IP address.
func (m *Manager) SupportsOriginalSourceAddr() bool {
	// Original source address use works if xt_socket match is supported, or if ip early demux
	// is disabled
	return m.haveSocketMatch || m.ipEarlyDemuxDisabled
}

// removeRules removes iptables rules installed by Cilium.
func (m *Manager) removeRules(prefix string) error {
	// Set of tables that have had iptables rules in any Cilium version
	tables := []string{"nat", "mangle", "raw", "filter"}
	for _, t := range tables {
		if err := m.removeCiliumRules(t, ip4tables, prefix+"CILIUM_"); err != nil {
			return err
		}

		if m.haveIp6tables {
			if err := m.removeCiliumRules(t, ip6tables, prefix+"CILIUM_"); err != nil {
				return err
			}
		}
	}

	for _, c := range ciliumChains {
		c.name = prefix + c.name
		if err := c.remove(true, m.haveIp6tables); err != nil {
			return err
		}
	}

	return nil
}

// renameChains renames iptables chains installed by Cilium.
func (m *Manager) renameChains(prefix string) error {
	for _, c := range ciliumChains {
		if err := c.rename(true, m.haveIp6tables, prefix+c.name); err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) inboundProxyRedirectRule(cmd string) []string {
	// Mark host proxy transparent connections to be routed to the local stack.
	// This comes before the TPROXY rules in the chain, and setting the mark
	// without the proxy port number will make the TPROXY rule to not match,
	// as we do not want to try to tproxy packets that are going to the stack
	// already.
	// This rule is needed for couple of reasons:
	// 1. route return traffic to the proxy
	// 2. route original direction traffic that would otherwise be intercepted
	//    by ip_early_demux
	toProxyMark := fmt.Sprintf("%#08x", linux_defaults.MagicMarkIsToProxy)
	matchFromIPSecEncrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkEncrypt, linux_defaults.RouteMarkMask)
	matchProxyToWorld := fmt.Sprintf("%#08x/%#08x", linux_defaults.MarkProxyToWorld, linux_defaults.RouteMarkMask)
	return []string{
		"-t", "mangle",
		cmd, ciliumPreMangleChain,
		"-m", "socket", "--transparent",
		"-m", "mark", "!", "--mark", matchFromIPSecEncrypt,
		"-m", "mark", "!", "--mark", matchProxyToWorld,
		"-m", "comment", "--comment", "cilium: any->pod redirect proxied traffic to host proxy",
		"-j", "MARK",
		"--set-mark", toProxyMark}
}

func (m *Manager) iptProxyRule(rules string, prog runnable, l4proto, ip string, proxyPort uint16, name string) error {
	// Match
	port := uint32(byteorder.HostToNetwork16(proxyPort)) << 16
	markMatch := fmt.Sprintf("%#x", linux_defaults.MagicMarkIsToProxy|port)
	// TPROXY params
	tProxyMark := fmt.Sprintf("%#x", linux_defaults.MagicMarkIsToProxy)
	tProxyPort := fmt.Sprintf("%d", proxyPort)

	existingRuleRegex := regexp.MustCompile(fmt.Sprintf("-A CILIUM_PRE_mangle -p %s -m mark --mark %s.*--on-ip %s", l4proto, markMatch, ip))
	if existingRuleRegex.MatchString(rules) {
		return nil
	}

	rule := []string{
		"-t", "mangle",
		"-A", ciliumPreMangleChain,
		"-p", l4proto,
		"-m", "mark", "--mark", markMatch,
		"-m", "comment", "--comment", "cilium: TPROXY to host " + name + " proxy",
		"-j", "TPROXY",
		"--tproxy-mark", tProxyMark,
		"--on-ip", ip,
		"--on-port", tProxyPort,
	}
	return prog.runProg(rule)
}

func (m *Manager) installStaticProxyRules() error {
	// match traffic to a proxy (upper 16 bits has the proxy port, which is masked out)
	matchToProxy := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsToProxy, linux_defaults.MagicMarkHostMask)
	// proxy return traffic has 0 ID in the mask
	matchProxyReply := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsProxy, linux_defaults.MagicMarkProxyNoIDMask)
	// proxy forward traffic
	matchProxyForward := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkEgress, linux_defaults.MagicMarkHostMask)
	// L7 proxy upstream return traffic has Endpoint ID in the mask
	matchL7ProxyUpstream := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsProxyEPID, linux_defaults.MagicMarkProxyMask)
	// match traffic from a proxy (either in forward or in return direction)
	matchFromProxy := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsProxy, linux_defaults.MagicMarkProxyMask)

	if m.sharedCfg.EnableIPv4 {
		// No conntrack for traffic to proxy
		if err := ip4tables.runProg([]string{
			"-t", "raw",
			"-A", ciliumPreRawChain,
			"-m", "mark", "--mark", matchToProxy,
			"-m", "comment", "--comment", "cilium: NOTRACK for proxy traffic",
			"-j", "CT", "--notrack"}); err != nil {
			return err
		}

		// Explicit ACCEPT for the proxy traffic. Needed when the INPUT defaults to DROP.
		// Matching needs to be the same as for the NOTRACK rule above.
		if err := ip4tables.runProg([]string{
			"-t", "filter",
			"-A", ciliumInputChain,
			"-m", "mark", "--mark", matchToProxy,
			"-m", "comment", "--comment", "cilium: ACCEPT for proxy traffic",
			"-j", "ACCEPT"}); err != nil {
			return err
		}

		// No conntrack for proxy return traffic that is heading to lxc+
		if err := ip4tables.runProg([]string{
			"-t", "raw",
			"-A", ciliumOutputRawChain,
			"-o", "lxc+",
			"-m", "mark", "--mark", matchProxyReply,
			"-m", "comment", "--comment", "cilium: NOTRACK for proxy return traffic",
			"-j", "CT", "--notrack"}); err != nil {
			return err
		}

		// No conntrack for proxy return traffic that is heading to cilium_host
		if err := ip4tables.runProg([]string{
			"-t", "raw",
			"-A", ciliumOutputRawChain,
			"-o", defaults.HostDevice,
			"-m", "mark", "--mark", matchProxyReply,
			"-m", "comment", "--comment", "cilium: NOTRACK for proxy return traffic",
			"-j", "CT", "--notrack"}); err != nil {
			return err
		}

		// No conntrack for proxy forward traffic that is heading to cilium_host
		if option.Config.EnableIPSec {
			if err := ip4tables.runProg([]string{
				"-t", "raw",
				"-A", ciliumOutputRawChain,
				"-o", defaults.HostDevice,
				"-m", "mark", "--mark", matchProxyForward,
				"-m", "comment", "--comment", "cilium: NOTRACK for proxy forward traffic",
				"-j", "CT", "--notrack"}); err != nil {
				return err
			}
		}

		// No conntrack for proxy upstream traffic that is heading to lxc+
		if err := ip4tables.runProg([]string{
			"-t", "raw",
			"-A", ciliumOutputRawChain,
			"-o", "lxc+",
			"-m", "mark", "--mark", matchL7ProxyUpstream,
			"-m", "comment", "--comment", "cilium: NOTRACK for L7 proxy upstream traffic",
			"-j", "CT", "--notrack"}); err != nil {
			return err
		}

		// No conntrack for proxy upstream traffic that is heading to cilium_host
		if err := ip4tables.runProg([]string{
			"-t", "raw",
			"-A", ciliumOutputRawChain,
			"-o", defaults.HostDevice,
			"-m", "mark", "--mark", matchL7ProxyUpstream,
			"-m", "comment", "--comment", "cilium: NOTRACK for L7 proxy upstream traffic",
			"-j", "CT", "--notrack"}); err != nil {
			return err
		}

		// Explicit ACCEPT for the proxy return traffic. Needed when the OUTPUT defaults to DROP.
		// Matching needs to be the same as for the NOTRACK rule above.
		if err := ip4tables.runProg([]string{
			"-t", "filter",
			"-A", ciliumOutputChain,
			"-m", "mark", "--mark", matchFromProxy,
			"-m", "comment", "--comment", "cilium: ACCEPT for proxy traffic",
			"-j", "ACCEPT"}); err != nil {
			return err
		}

		// Explicit ACCEPT for the l7 proxy upstream traffic. Needed when the OUTPUT defaults to DROP.
		// TODO: See if this is really needed. We do not have an ACCEPT for normal proxy upstream traffic.
		if err := ip4tables.runProg([]string{
			"-t", "filter",
			"-A", ciliumOutputChain,
			"-m", "mark", "--mark", matchL7ProxyUpstream,
			"-m", "comment", "--comment", "cilium: ACCEPT for l7 proxy upstream traffic",
			"-j", "ACCEPT"}); err != nil {
			return err
		}

		if m.haveSocketMatch {
			// Direct inbound TPROXYed traffic towards the socket
			if err := ip4tables.runProg(m.inboundProxyRedirectRule("-A")); err != nil {
				return err
			}
		}
	}

	if m.sharedCfg.EnableIPv6 {
		// No conntrack for traffic to ingress proxy
		if err := ip6tables.runProg([]string{
			"-t", "raw",
			"-A", ciliumPreRawChain,
			"-m", "mark", "--mark", matchToProxy,
			"-m", "comment", "--comment", "cilium: NOTRACK for proxy traffic",
			"-j", "CT", "--notrack"}); err != nil {
			return err
		}

		// Explicit ACCEPT for the proxy traffic. Needed when the INPUT defaults to DROP.
		// Matching needs to be the same as for the NOTRACK rule above.
		if err := ip6tables.runProg([]string{
			"-t", "filter",
			"-A", ciliumInputChain,
			"-m", "mark", "--mark", matchToProxy,
			"-m", "comment", "--comment", "cilium: ACCEPT for proxy traffic",
			"-j", "ACCEPT"}); err != nil {
			return err
		}

		// No conntrack for proxy return traffic that is heading to cilium_host
		if err := ip6tables.runProg([]string{
			"-t", "raw",
			"-A", ciliumOutputRawChain,
			"-o", defaults.HostDevice,
			"-m", "mark", "--mark", matchProxyReply,
			"-m", "comment", "--comment", "cilium: NOTRACK for proxy return traffic",
			"-j", "CT", "--notrack"}); err != nil {
			return err
		}

		// No conntrack for proxy upstream traffic that is heading to lxc+
		if err := ip6tables.runProg([]string{
			"-t", "raw",
			"-A", ciliumOutputRawChain,
			"-o", "lxc+",
			"-m", "mark", "--mark", matchProxyReply,
			"-m", "comment", "--comment", "cilium: NOTRACK for proxy return traffic",
			"-j", "CT", "--notrack"}); err != nil {
			return err
		}

		// Explicit ACCEPT for the proxy return traffic. Needed when the OUTPUT defaults to DROP.
		// Matching needs to be the same as for the NOTRACK rule above.
		if err := ip6tables.runProg([]string{
			"-t", "filter",
			"-A", ciliumOutputChain,
			"-m", "mark", "--mark", matchFromProxy,
			"-m", "comment", "--comment", "cilium: ACCEPT for proxy traffic",
			"-j", "ACCEPT"}); err != nil {
			return err
		}

		if m.haveSocketMatch {
			// Direct inbound TPROXYed traffic towards the socket
			if err := ip6tables.runProg(m.inboundProxyRedirectRule("-A")); err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *Manager) doCopyProxyRules(prog iptablesInterface, table string, re *regexp.Regexp, match, oldChain, newChain string) error {
	rules, err := prog.runProgOutput([]string{"-t", table, "-S"})
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(strings.NewReader(rules))
	for scanner.Scan() {
		rule := scanner.Text()
		if !re.MatchString(rule) || !strings.Contains(rule, match) {
			continue
		}

		args, err := shellwords.Parse(strings.Replace(rule, oldChain, newChain, 1))
		if err != nil {
			log.WithFields(logrus.Fields{
				"table":          table,
				"prog":           prog.getProg(),
				logfields.Object: rule,
			}).WithError(err).Warn("Unable to parse TPROXY rule, disruption to traffic selected by L7 policy possible")
			continue
		}

		copyRule := append([]string{"-t", table}, args...)
		if err := prog.runProg(copyRule); err != nil {
			return err
		}
	}

	return nil
}

var tproxyMatch = regexp.MustCompile("CILIUM_PRE_mangle .*cilium: TPROXY")

// copies old proxy rules
func (m *Manager) copyProxyRules(oldChain string, match string) error {
	if m.sharedCfg.EnableIPv4 {
		if err := m.doCopyProxyRules(ip4tables, "mangle", tproxyMatch, match, oldChain, ciliumPreMangleChain); err != nil {
			return err
		}
	}

	if m.sharedCfg.EnableIPv6 {
		if err := m.doCopyProxyRules(ip6tables, "mangle", tproxyMatch, match, oldChain, ciliumPreMangleChain); err != nil {
			return err
		}
	}

	return nil
}

// Redirect packets to the host proxy via TPROXY, as directed by the Cilium
// datapath bpf programs via skb marks.
func (m *Manager) addProxyRules(prog runnable, ip string, proxyPort uint16, name string) error {
	rules, err := prog.runProgOutput([]string{"-t", "mangle", "-S"})
	if err != nil {
		return err
	}

	for _, proto := range []string{"tcp", "udp"} {
		if err := m.iptProxyRule(rules, prog, proto, ip, proxyPort, name); err != nil {
			return err
		}
	}

	// Delete all other rules for this same proxy name
	// These may accumulate if there is a bind failure on a previously used port
	portAndIPMatch := fmt.Sprintf("TPROXY --on-port %d --on-ip %s ", proxyPort, ip)
	scanner := bufio.NewScanner(strings.NewReader(rules))
	for scanner.Scan() {
		rule := scanner.Text()
		if !strings.Contains(rule, "-A CILIUM_PRE_mangle ") || !strings.Contains(rule, "cilium: TPROXY to host "+name) || strings.Contains(rule, portAndIPMatch) {
			continue
		}

		args, err := shellwords.Parse(strings.Replace(rule, "-A", "-D", 1))
		if err != nil {
			log.WithError(err).WithField(logfields.Object, rule).Warnf("Unable to parse %s TPROXY rule", prog)
			continue
		}

		deleteRule := append([]string{"-t", "mangle"}, args...)
		if err := prog.runProg(deleteRule); err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) endpointNoTrackRules(prog runnable, cmd string, IP string, port *lb.L4Addr) error {
	var err error

	protocol := strings.ToLower(port.Protocol)
	p := strconv.FormatUint(uint64(port.Port), 10)

	// currently the only use case for this is node-local-dns
	// with LRP, node-local-dns should be deployed as a non-host-namespaced
	// pod and  we want to skip kernel conntrack for any traffic between the
	// application pod and the node-local-dns pod
	// There are 4 types of packets that we want to skip conntrack:
	// 1. From a non-host pod to the node-local-dns pod
	// 2. From the node-local-dns pod to a non-host pod
	// 3. From a hostNetwork pod to the node-local-dns pod
	// 4. From the node-local-dns pod to a hostNetwork pod

	// 1. The following 2 rules cover packets from non-host pod to node-local-dns
	if err = prog.runProg([]string{
		"-t", "raw",
		cmd, ciliumPreRawChain,
		"-p", protocol,
		"-d", IP,
		"--dport", p,
		"-j", "CT",
		"--notrack"}); err != nil {
		log.WithError(err).Warning("Failed to enforce endpoint notrack")
	}
	if err = prog.runProg([]string{
		"-t", "filter",
		cmd, ciliumForwardChain,
		"-p", protocol,
		"-d", IP,
		"--dport",
		p, "-j",
		"ACCEPT"}); err != nil {
		log.WithError(err).Warning("Failed to enforce endpoint notrack")
	}

	// 2. The following 2 rules cover packets from node-local-dns to
	// non-host pod
	if err = prog.runProg([]string{
		"-t", "raw",
		cmd, ciliumPreRawChain,
		"-p", protocol,
		"-s", IP,
		"--sport", p,
		"-j", "CT",
		"--notrack"}); err != nil {
		log.WithError(err).Warning("Failed to enforce endpoint notrack")
	}
	if err = prog.runProg([]string{
		"-t", "filter",
		cmd, ciliumForwardChain,
		"-p", protocol,
		"-s", IP,
		"--sport",
		p, "-j",
		"ACCEPT"}); err != nil {
		log.WithError(err).Warning("Failed to enforce endpoint notrack")
	}

	// 3. The following 2 rules cover packets from host namespaced pod to
	// node-local-dns
	if err = prog.runProg([]string{
		"-t", "raw",
		cmd, ciliumOutputRawChain,
		"-p", protocol,
		"-d", IP,
		"--dport", p,
		"-j", "CT",
		"--notrack"}); err != nil {
		log.WithError(err).Warning("Failed to enforce endpoint notrack")
	}
	if err = prog.runProg([]string{
		"-t", "filter",
		cmd, ciliumOutputChain,
		"-p", protocol,
		"-d", IP,
		"--dport", p,
		"-j", "ACCEPT"}); err != nil {
		log.WithError(err).Warning("Failed to enforce endpoint notrack")
	}

	// 4. The following rule (and the prerouting rule in case 2)
	// covers packets from node-local-dns to host namespaced pod
	if err = prog.runProg([]string{
		"-t", "filter",
		cmd, ciliumInputChain,
		"-p", protocol,
		"-s", IP,
		"--sport",
		p, "-j",
		"ACCEPT"}); err != nil {
		log.WithError(err).Warning("Failed to enforce endpoint notrack")
	}

	// The following rules are kept for compatibility with host-namespaced
	// node-local-dns if user already deploys in the legacy mode without
	// LRP.
	if err = prog.runProg([]string{
		"-t", "raw",
		cmd, ciliumOutputRawChain,
		"-p", protocol,
		"-s", IP,
		"--sport", p,
		"-j", "CT",
		"--notrack"}); err != nil {
		log.WithError(err).Warning("Failed to enforce endpoint notrack")
	}
	if err = prog.runProg([]string{
		"-t", "filter",
		cmd, ciliumOutputChain,
		"-p", protocol,
		"-s", IP,
		"--sport", p,
		"-j", "ACCEPT"}); err != nil {
		log.WithError(err).Warning("Failed to enforce endpoint notrack")
	}
	if err = prog.runProg([]string{
		"-t", "filter",
		cmd, ciliumInputChain,
		"-p", protocol,
		"-d", IP,
		"--dport",
		p, "-j",
		"ACCEPT"}); err != nil {
		log.WithError(err).Warning("Failed to enforce endpoint notrack")
	}
	return err
}

// InstallNoTrackRules is explicitly called when a pod has valid "policy.cilium.io/no-track-port" annotation.
// When InstallNoConntrackIptRules flag is set, a super set of v4 NOTRACK rules will be automatically
// installed upon agent bootstrap (via function addNoTrackPodTrafficRules) and this function will be skipped.
// When InstallNoConntrackIptRules is not set, this function will be executed to install NOTRACK rules.
// The rules installed by this function is very specific, for now, the only user is node-local-dns pods.
func (m *Manager) InstallNoTrackRules(ip netip.Addr, port uint16) {
	if m.skipPodTrafficConntrack(ip) {
		return
	}

	reconciled := make(chan struct{})
	m.reconcilerParams.addNoTrackPod <- reconciliationRequest[noTrackPodInfo]{noTrackPodInfo{ip, port}, reconciled}
	<-reconciled
}

// See comments for InstallNoTrackRules.
func (m *Manager) RemoveNoTrackRules(ip netip.Addr, port uint16) {
	if m.skipPodTrafficConntrack(ip) {
		return
	}

	reconciled := make(chan struct{})
	m.reconcilerParams.delNoTrackPod <- reconciliationRequest[noTrackPodInfo]{noTrackPodInfo{ip, port}, reconciled}
	<-reconciled
}

func (m *Manager) InstallProxyRules(proxyPort uint16, name string) {
	reconciled := make(chan struct{})
	m.reconcilerParams.proxies <- reconciliationRequest[proxyInfo]{proxyInfo{name, proxyPort}, reconciled}
	<-reconciled
}

func (m *Manager) doInstallProxyRules(proxyPort uint16, name string) error {
	if m.haveBPFSocketAssign {
		log.WithField("port", proxyPort).
			Debug("Skipping proxy rule install due to BPF support")
		return nil
	}

	if m.sharedCfg.EnableIPv4 {
		if err := m.addProxyRules(ip4tables, "127.0.0.1", proxyPort, name); err != nil {
			return err
		}
	}
	if m.sharedCfg.EnableIPv6 {
		if err := m.addProxyRules(ip6tables, "::1", proxyPort, name); err != nil {
			return err
		}
	}

	return nil
}

// GetProxyPorts enumerates all existing TPROXY rules in the datapath installed earlier with
// InstallProxyRules and returns all proxy ports found.
func (m *Manager) GetProxyPorts() map[string]uint16 {
	prog := ip4tables
	if !m.sharedCfg.EnableIPv4 {
		prog = ip6tables
	}

	return m.doGetProxyPorts(prog)
}

func (m *Manager) doGetProxyPorts(prog iptablesInterface) map[string]uint16 {
	portMap := make(map[string]uint16)

	m.lock.Lock()
	defer m.lock.Unlock()

	rules, err := prog.runProgOutput([]string{"-t", "mangle", "-n", "-L", ciliumPreMangleChain})
	if err != nil {
		return portMap
	}

	re := regexp.MustCompile(
		"(cilium-[^ ]*) proxy.*TPROXY redirect " +
			"(0.0.0.0|" + ipfamily.IPv4().Localhost +
			"|::|" + ipfamily.IPv6().Localhost + ")" +
			":([1-9][0-9]*) mark",
	)
	strs := re.FindAllString(rules, -1)
	for _, str := range strs {
		// Pick the name and port number from each match
		name := re.ReplaceAllString(str, "$1")
		portStr := re.ReplaceAllString(str, "$3")
		portUInt64, err := strconv.ParseUint(portStr, 10, 16)
		if err == nil {
			portMap[name] = uint16(portUInt64)
		}
	}
	return portMap
}

func (m *Manager) getDeliveryInterface(ifName string) string {
	switch {
	case m.sharedCfg.EnableEndpointRoutes:
		// aws-cni creates container interfaces with names like eni621c0fc8425.
		if m.cniConfigManager.GetChainingMode() == "aws-cni" {
			return "eni+"
		}
		return "lxc+"

	case m.sharedCfg.IPAM == ipamOption.IPAMENI ||
		m.sharedCfg.IPAM == ipamOption.IPAMAlibabaCloud:
		return "lxc+"

	default:
		return ifName
	}
}

func (m *Manager) installForwardChainRules(ifName, localDeliveryInterface, forwardChain string) error {
	if m.sharedCfg.EnableIPv4 {
		if err := m.installForwardChainRulesIpX(ip4tables, ifName, localDeliveryInterface, forwardChain); err != nil {
			return err
		}
	}
	if m.sharedCfg.EnableIPv6 {
		return m.installForwardChainRulesIpX(ip6tables, ifName, localDeliveryInterface, forwardChain)
	}

	return nil
}

func (m *Manager) installForwardChainRulesIpX(prog runnable, ifName, localDeliveryInterface, forwardChain string) error {
	// While kube-proxy does change the policy of the iptables FORWARD chain
	// it doesn't seem to handle all cases, e.g. host network pods that use
	// the node IP which would still end up in default DENY. Similarly, for
	// plain Docker setup, we would otherwise hit default DENY in FORWARD chain.
	// Also, k8s 1.15 introduced "-m conntrack --ctstate INVALID -j DROP" which
	// in the direct routing case can drop EP replies.
	//
	// Therefore, add the rules below to avoid having a user to manually opt-in.
	// See also: https://github.com/kubernetes/kubernetes/issues/39823
	// In here can only be basic ACCEPT rules, nothing more complicated.
	//
	// The 2nd and 3rd rule are for the case of nodeport traffic where the backend is
	// remote. The traffic flow in FORWARD is as follows:
	//
	//  - Node serving nodeport request:
	//      IN=eno1 OUT=cilium_host
	//      IN=cilium_host OUT=eno1
	//
	//  - Node running backend:
	//       IN=eno1 OUT=cilium_host
	//       IN=lxc... OUT=eno1
	if err := prog.runProg([]string{
		"-A", forwardChain,
		"-o", ifName,
		"-m", "comment", "--comment", "cilium: any->cluster on " + ifName + " forward accept",
		"-j", "ACCEPT"}); err != nil {
		return err
	}
	if err := prog.runProg([]string{
		"-A", forwardChain,
		"-i", ifName,
		"-m", "comment", "--comment", "cilium: cluster->any on " + ifName + " forward accept (nodeport)",
		"-j", "ACCEPT"}); err != nil {
		return err
	}
	if err := prog.runProg([]string{
		"-A", forwardChain,
		"-i", "lxc+",
		"-m", "comment", "--comment", "cilium: cluster->any on lxc+ forward accept",
		"-j", "ACCEPT"}); err != nil {
		return err
	}
	// Proxy return traffic to a remote source needs '-i cilium_net'.
	if ifName == defaults.HostDevice {
		ifPeerName := defaults.SecondHostDevice
		if err := prog.runProg([]string{
			"-A", forwardChain,
			"-i", ifPeerName,
			"-m", "comment", "--comment", "cilium: cluster->any on " + ifPeerName + " forward accept (nodeport)",
			"-j", "ACCEPT"}); err != nil {
			return err
		}
	}
	// In case the delivery interface and the host interface are not the
	// same (enable-endpoint-routes), a separate set of rules to allow
	// from/to delivery interface is required.
	if localDeliveryInterface != ifName {
		if err := prog.runProg([]string{
			"-A", forwardChain,
			"-o", localDeliveryInterface,
			"-m", "comment", "--comment", "cilium: any->cluster on " + localDeliveryInterface + " forward accept",
			"-j", "ACCEPT"}); err != nil {
			return err
		}
		if err := prog.runProg([]string{
			"-A", forwardChain,
			"-i", localDeliveryInterface,
			"-m", "comment", "--comment", "cilium: cluster->any on " + localDeliveryInterface + " forward accept (nodeport)",
			"-j", "ACCEPT"}); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) installMasqueradeRules(
	prog iptablesInterface, nativeDevices []string,
	localDeliveryInterface, snatDstExclusionCIDR, allocRange, hostMasqueradeIP string,
) error {
	devices := nativeDevices

	if m.sharedCfg.NodeIpsetNeeded {
		// Exclude traffic to nodes from masquerade.
		progArgs := []string{
			"-t", "nat",
			"-A", ciliumPostNatChain,
		}

		// If MasqueradeInterfaces is set, we need to mirror base condition of the
		// "cilium masquerade non-cluster" rule below, as the allocRange might not
		// be valid in such setups (e.g. in ENI mode).
		if len(m.sharedCfg.MasqueradeInterfaces) > 0 {
			progArgs = append(progArgs, "-o", strings.Join(m.sharedCfg.MasqueradeInterfaces, ","))
		} else {
			progArgs = append(progArgs, "-s", allocRange)
		}

		progArgs = append(progArgs,
			"-m", "set", "--match-set", prog.getIpset(), "dst",
			"-m", "comment", "--comment", "exclude traffic to cluster nodes from masquerade",
			"-j", "ACCEPT",
		)
		if err := prog.runProg(progArgs); err != nil {
			return err
		}
	}

	// Masquerade egress traffic leaving the node based on source routing
	//
	// If this option is enabled, then it takes precedence over the catch-all
	// MASQUERADE further below.
	if m.sharedCfg.EnableMasqueradeRouteSource {
		var defaultRoutes []netlink.Route

		if len(m.sharedCfg.MasqueradeInterfaces) > 0 {
			devices = m.sharedCfg.MasqueradeInterfaces
		}
		family := netlink.FAMILY_V4
		if prog == ip6tables {
			family = netlink.FAMILY_V6
		}
		initialPass := true
		if routes, err := netlink.RouteList(nil, family); err == nil {
		nextPass:
			for _, r := range routes {
				var link netlink.Link
				match := false
				if r.LinkIndex > 0 {
					link, err = netlink.LinkByIndex(r.LinkIndex)
					if err != nil {
						continue
					}
					// Routes are dedicated to the specific interface, so we
					// need to install the SNAT rules also for that interface
					// via -o. If we cannot correlate to anything because no
					// devices were specified, we need to bail out.
					if len(devices) == 0 {
						return fmt.Errorf("cannot correlate source route device for generating masquerading rules")
					}
					for _, device := range devices {
						if device == link.Attrs().Name {
							match = true
							break
						}
					}
				} else {
					// There might be next hop groups where ifindex is zero
					// and the underlying next hop devices might not be known
					// to Cilium. In this case, assume match and don't encode
					// -o device.
					match = true
				}
				_, exclusionCIDR, err := net.ParseCIDR(snatDstExclusionCIDR)
				if !match || r.Src == nil || (err == nil && cidr.Equal(r.Dst, exclusionCIDR)) {
					continue
				}
				if initialPass && cidr.Equal(r.Dst, cidr.ZeroNet(r.Family)) {
					defaultRoutes = append(defaultRoutes, r)
					continue
				}
				progArgs := []string{
					"-t", "nat",
					"-A", ciliumPostNatChain,
					"-s", allocRange,
				}
				if cidr.Equal(r.Dst, cidr.ZeroNet(r.Family)) {
					progArgs = append(
						progArgs,
						"!", "-d", snatDstExclusionCIDR)
				} else {
					progArgs = append(
						progArgs,
						"-d", r.Dst.String())
				}
				if link != nil {
					progArgs = append(
						progArgs,
						"-o", link.Attrs().Name)
				} else {
					progArgs = append(
						progArgs,
						"!", "-o", "cilium_+")
				}
				progArgs = append(
					progArgs,
					"-m", "comment", "--comment", "cilium snat non-cluster via source route",
					"-j", "SNAT",
					"--to-source", r.Src.String())
				if m.cfg.IPTablesRandomFully {
					progArgs = append(progArgs, "--random-fully")
				}
				if err := prog.runProg(progArgs); err != nil {
					return err
				}
			}
			if initialPass {
				initialPass = false
				routes = defaultRoutes
				goto nextPass
			}
		}
	} else {
		// Masquerade all egress traffic leaving the node (catch-all)
		//
		// This rule must be first as the node ipset rule as it has different
		// exclusion criteria than the other rules in this table.
		//
		// The following conditions must be met:
		// * May not leave on a cilium_ interface, this excludes all
		//   tunnel traffic
		// * Must originate from an IP in the local allocation range
		// * Must not be reply if BPF NodePort is enabled
		// * Tunnel mode:
		//   * May not be targeted to an IP in the local allocation
		//     range
		// * Non-tunnel mode:
		//   * May not be targeted to an IP in the cluster range
		progArgs := []string{
			"-t", "nat",
			"-A", ciliumPostNatChain,
			"!", "-d", snatDstExclusionCIDR,
		}
		if len(m.sharedCfg.MasqueradeInterfaces) > 0 {
			progArgs = append(
				progArgs,
				"-o", strings.Join(m.sharedCfg.MasqueradeInterfaces, ","))
		} else {
			progArgs = append(
				progArgs,
				"-s", allocRange,
				"!", "-o", "cilium_+")
		}
		progArgs = append(
			progArgs,
			"-m", "comment", "--comment", "cilium masquerade non-cluster",
			"-j", "MASQUERADE")
		if m.cfg.IPTablesRandomFully {
			progArgs = append(progArgs, "--random-fully")
		}
		if err := prog.runProg(progArgs); err != nil {
			return err
		}
	}

	// The following rule exclude traffic from the remaining rules in this chain.
	// If this rule matches, none of the remaining rules in this chain
	// are considered.

	// Exclude proxy return traffic from the masquarade rules.
	if err := prog.runProg([]string{
		"-t", "nat",
		"-A", ciliumPostNatChain,
		// Don't match proxy (return) traffic
		"-m", "mark", "--mark", fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsProxy, linux_defaults.MagicMarkProxyMask),
		"-m", "comment", "--comment", "exclude proxy return traffic from masquerade",
		"-j", "ACCEPT"}); err != nil {
		return err
	}

	if m.sharedCfg.TunnelingEnabled {
		// Masquerade all traffic from the host into the ifName
		// interface if the source is not in the node's pod CIDR.
		//
		// The following conditions must be met:
		// * Must be targeted for the ifName interface
		// * Must be targeted to an IP that is not local
		// * May not already be originating from the node's pod CIDR.
		if err := prog.runProg([]string{
			"-t", "nat",
			"-A", ciliumPostNatChain,
			"!", "-s", allocRange,
			"!", "-d", allocRange,
			"-o", defaults.HostDevice,
			"-m", "comment", "--comment", "cilium host->cluster masquerade",
			"-j", "SNAT", "--to-source", hostMasqueradeIP}); err != nil {
			return err
		}
	}

	loopbackAddr := "127.0.0.1"
	if prog == ip6tables {
		loopbackAddr = "::1"
	}

	// Masquerade all traffic from the host into local
	// endpoints if the source is 127.0.0.1. This is
	// required to force replies out of the endpoint's
	// network namespace.
	//
	// The following conditions must be met:
	// * Must be targeted for local endpoint
	// * Must be from 127.0.0.1
	if err := prog.runProg([]string{
		"-t", "nat",
		"-A", ciliumPostNatChain,
		"-s", loopbackAddr,
		"-o", localDeliveryInterface,
		"-m", "comment", "--comment", "cilium host->cluster from " + loopbackAddr + " masquerade",
		"-j", "SNAT", "--to-source", hostMasqueradeIP}); err != nil {
		return err
	}

	// Masquerade all traffic that originated from a local
	// pod and thus carries a security identity and that
	// was also DNAT'ed. It must be masqueraded to ensure
	// that reverse NAT can be performed. Otherwise the
	// reply traffic would be sent directly to the pod
	// without traversing the Linux stack again.
	//
	// This is only done if EnableEndpointRoutes is
	// disabled, if EnableEndpointRoutes is enabled, then
	// all traffic always passes through the stack anyway.
	//
	// This is required for:
	//  - portmap/host if both source and destination are
	//    on the same node
	//  - kiam if source and server are on the same node
	if !m.sharedCfg.EnableEndpointRoutes {
		if err := prog.runProg([]string{
			"-t", "nat",
			"-A", ciliumPostNatChain,
			"-m", "mark", "--mark", fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIdentity, linux_defaults.MagicMarkHostMask),
			"-o", localDeliveryInterface,
			"-m", "conntrack", "--ctstate", "DNAT",
			"-m", "comment", "--comment", "hairpin traffic that originated from a local pod",
			"-j", "SNAT", "--to-source", hostMasqueradeIP}); err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) installHostTrafficMarkRule(prog runnable) error {
	// Mark all packets sourced from processes running on the host with a
	// special marker so that we can differentiate traffic sourced locally
	// vs. traffic from the outside world that was masqueraded to appear
	// like it's from the host.
	//
	// Originally we set this mark only for traffic destined to the
	// ifName device, to ensure that any traffic directly reaching
	// to a Cilium-managed IP could be classified as from the host.
	//
	// However, there's another case where a local process attempts to
	// reach a service IP which is backed by a Cilium-managed pod. The
	// service implementation is outside of Cilium's control, for example,
	// handled by kube-proxy. We can tag even this traffic with a magic
	// mark, then when the service implementation proxies it back into
	// Cilium the BPF will see this mark and understand that the packet
	// originated from the host.
	matchFromIPSecEncrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkDecrypt, linux_defaults.RouteMarkMask)
	matchFromIPSecDecrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkEncrypt, linux_defaults.RouteMarkMask)
	matchOverlay := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkOverlay, linux_defaults.MagicMarkHostMask)
	matchFromProxy := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsProxy, linux_defaults.MagicMarkProxyMask)
	matchFromProxyEPID := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsProxyEPID, linux_defaults.MagicMarkProxyMask)
	matchFromDNSProxy := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIdentity, linux_defaults.MagicMarkHostMask)
	markAsFromHost := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkHost, linux_defaults.MagicMarkHostMask)

	return prog.runProg([]string{
		"-t", "filter",
		"-A", ciliumOutputChain,
		"-m", "mark", "!", "--mark", matchFromIPSecDecrypt, // Don't match ipsec traffic
		"-m", "mark", "!", "--mark", matchFromIPSecEncrypt, // Don't match ipsec traffic
		"-m", "mark", "!", "--mark", matchOverlay, // Don't match Cilium's overlay traffic
		"-m", "mark", "!", "--mark", matchFromProxy, // Don't match proxy traffic
		"-m", "mark", "!", "--mark", matchFromProxyEPID, // Don't match proxy traffic
		"-m", "mark", "!", "--mark", matchFromDNSProxy, // Don't match DNS proxy egress traffic
		"-m", "comment", "--comment", "cilium: host->any mark as from host",
		"-j", "MARK", "--set-xmark", markAsFromHost})
}

func (m *Manager) doInstallRules(state desiredState, firstInit bool) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	// Make sure we have no old "backups"
	if err := m.removeRules(oldCiliumPrefix); err != nil {
		return fmt.Errorf("failed to remove old backup rules: %w", err)
	}

	if err := m.renameChains(oldCiliumPrefix); err != nil {
		return fmt.Errorf("failed to rename chains: %w", err)
	}

	// install rules if needed
	if state.installRules {
		if err := m.installRules(state); err != nil {
			return fmt.Errorf("failed to install rules: %w", err)
		}

		// copy old proxy rules over at initialization
		if firstInit {
			if err := m.copyProxyRules(oldCiliumPrefix+ciliumPreMangleChain, "cilium-dns-egress"); err != nil {
				return fmt.Errorf("cannot copy old proxy rules, disruption to traffic selected by L7 policy possible: %w", err)
			}
		}

		for _, proxy := range state.proxies {
			if err := m.doInstallProxyRules(proxy.port, proxy.name); err != nil {
				return fmt.Errorf("cannot install proxy rules for %s: %w", proxy.name, err)
			}
		}
	}

	if err := m.removeRules(oldCiliumPrefix); err != nil {
		return fmt.Errorf("failed to remove old rules: %w", err)
	}

	return nil
}

// installRules installs iptables rules for Cilium in specific use-cases
// (most specifically, interaction with kube-proxy).
func (m *Manager) installRules(state desiredState) error {
	// Install new rules
	for _, c := range ciliumChains {
		if err := c.add(m.sharedCfg.EnableIPv4, m.sharedCfg.EnableIPv6); err != nil {
			// do not return error for chain creation that are linked to disabled feeder rules
			if isDisabledChain(m.cfg.DisableIptablesFeederRules, c.hook) {
				log.WithField(logfields.Chain, c.name).Warningf("ignoring creation of chain since feeder rules for %s is disabled", c.hook)
				continue
			}

			return fmt.Errorf("cannot add custom chain %s: %w", c.name, err)
		}
	}

	if err := m.installStaticProxyRules(); err != nil {
		return fmt.Errorf("cannot install static proxy rules: %w", err)
	}

	if err := m.addCiliumAcceptXfrmRules(); err != nil {
		return fmt.Errorf("cannot install xfrm rules: %w", err)
	}

	localDeliveryInterface := m.getDeliveryInterface(defaults.HostDevice)

	if err := m.installForwardChainRules(defaults.HostDevice, localDeliveryInterface, ciliumForwardChain); err != nil {
		return fmt.Errorf("cannot install forward chain rules to %s: %w", ciliumForwardChain, err)
	}

	if m.sharedCfg.EnableIPv4 {
		if err := m.installHostTrafficMarkRule(ip4tables); err != nil {
			return fmt.Errorf("cannot install host traffic mark rule: %w", err)
		}

		if m.sharedCfg.IptablesMasqueradingIPv4Enabled && state.localNodeInfo.internalIPv4 != nil {
			if err := m.installMasqueradeRules(ip4tables, state.devices.UnsortedList(), localDeliveryInterface,
				m.remoteSNATDstAddrExclusionCIDR(state.localNodeInfo.ipv4NativeRoutingCIDR, state.localNodeInfo.ipv4AllocCIDR),
				state.localNodeInfo.ipv4AllocCIDR,
				state.localNodeInfo.internalIPv4.String(),
			); err != nil {
				return fmt.Errorf("cannot install masquerade rules: %w", err)
			}
		}
	}

	if m.sharedCfg.EnableIPv6 {
		if err := m.installHostTrafficMarkRule(ip6tables); err != nil {
			return fmt.Errorf("cannot install host traffic mark rule: %w", err)
		}

		if m.sharedCfg.IptablesMasqueradingIPv6Enabled && state.localNodeInfo.internalIPv6 != nil {
			if err := m.installMasqueradeRules(ip6tables, state.devices.UnsortedList(), localDeliveryInterface,
				m.remoteSNATDstAddrExclusionCIDR(state.localNodeInfo.ipv6NativeRoutingCIDR, state.localNodeInfo.ipv6AllocCIDR),
				state.localNodeInfo.ipv6AllocCIDR,
				state.localNodeInfo.internalIPv6.String(),
			); err != nil {
				return fmt.Errorf("cannot install masquerade rules: %w", err)
			}
		}
	}

	// AWS ENI requires to mark packets ingressing on the primary interface
	// and route them back the same way even if the pod responding is using
	// the IP of a different interface. Please see note in Reinitialize()
	// in pkg/datapath/loader for more details.
	if m.sharedCfg.IPAM == ipamOption.IPAMENI || m.sharedCfg.IPAM == ipamOption.IPAMAlibabaCloud {
		if err := m.addCiliumENIRules(); err != nil {
			return fmt.Errorf("cannot install rules for ENI multi-node NodePort: %w", err)
		}
	}

	if m.sharedCfg.EnableIPSec {
		if err := m.addCiliumNoTrackXfrmRules(); err != nil {
			return fmt.Errorf("cannot install xfrm rules: %w", err)
		}
	}

	podsCIDR := state.localNodeInfo.ipv4NativeRoutingCIDR
	if m.sharedCfg.InstallNoConntrackIptRules && podsCIDR != "" {
		if err := m.addNoTrackPodTrafficRules(ip4tables, podsCIDR); err != nil {
			return fmt.Errorf("cannot install pod traffic no CT rules: %w", err)
		}
	}

	for noTrackPodInfo := range state.noTrackPods {
		if err := m.installNoTrackRules(noTrackPodInfo.ip, noTrackPodInfo.port); err != nil {
			return err
		}
	}

	for _, c := range ciliumChains {
		// do not install feeder for chains that are set to be disabled
		if isDisabledChain(m.cfg.DisableIptablesFeederRules, c.hook) {
			log.WithField(logfields.Chain, c.hook).Infof("Skipping the install of feeder rule")
			continue
		}

		if err := c.installFeeder(m.sharedCfg.EnableIPv4, m.sharedCfg.EnableIPv6, m.cfg.PrependIptablesChains); err != nil {
			return fmt.Errorf("cannot install feeder rule: %w", err)
		}
	}

	return nil
}

func (m *Manager) remoteSNATDstAddrExclusionCIDR(nativeRoutingCIDR, allocCIDR string) string {
	if nativeRoutingCIDR != "" {
		// ip{v4,v6}-native-routing-cidr is set, so use it
		return nativeRoutingCIDR
	}

	return allocCIDR
}

func (m *Manager) ciliumNoTrackXfrmRules(prog iptablesInterface, input string) error {
	matchFromIPSecEncrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkDecrypt, linux_defaults.RouteMarkMask)
	matchFromIPSecDecrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkEncrypt, linux_defaults.RouteMarkMask)

	for _, match := range []string{matchFromIPSecDecrypt, matchFromIPSecEncrypt} {
		if err := prog.runProg([]string{
			"-t", "raw", input, ciliumPreRawChain,
			"-m", "mark", "--mark", match,
			"-m", "comment", "--comment", xfrmDescription,
			"-j", "CT", "--notrack"}); err != nil {
			return err
		}
	}
	return nil
}

// Exclude crypto traffic from the filter and nat table rules.
// This avoids encryption bits and keyID, 0x*d00 for decryption
// and 0x*e00 for encryption, colliding with existing rules. Needed
// for kube-proxy for example.
func (m *Manager) addCiliumAcceptXfrmRules() error {
	if !m.sharedCfg.EnableIPSec {
		return nil
	}

	insertAcceptXfrm := func(ipt *ipt, table, chain string) error {
		matchFromIPSecEncrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkDecrypt, linux_defaults.RouteMarkMask)
		matchFromIPSecDecrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkEncrypt, linux_defaults.RouteMarkMask)

		comment := "exclude xfrm marks from " + table + " " + chain + " chain"

		if err := ipt.runProg([]string{
			"-t", table,
			"-A", chain,
			"-m", "mark", "--mark", matchFromIPSecEncrypt,
			"-m", "comment", "--comment", comment,
			"-j", "ACCEPT"}); err != nil {
			return err
		}

		return ipt.runProg([]string{
			"-t", table,
			"-A", chain,
			"-m", "mark", "--mark", matchFromIPSecDecrypt,
			"-m", "comment", "--comment", comment,
			"-j", "ACCEPT"})
	}

	for _, chain := range ciliumChains {
		switch chain.table {
		case "filter", "nat":
			if m.sharedCfg.EnableIPv4 {
				if err := insertAcceptXfrm(ip4tables, chain.table, chain.name); err != nil {
					return err
				}
			}
			// ip6tables chain exists only if chain.ipv6 is true
			if m.sharedCfg.EnableIPv6 && chain.ipv6 {
				if err := insertAcceptXfrm(ip6tables, chain.table, chain.name); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (m *Manager) addCiliumNoTrackXfrmRules() (err error) {
	if m.sharedCfg.EnableIPv4 {
		if err = m.ciliumNoTrackXfrmRules(ip4tables, "-I"); err != nil {
			return
		}
	}
	if m.sharedCfg.EnableIPv6 {
		return m.ciliumNoTrackXfrmRules(ip6tables, "-I")
	}
	return nil
}

func (m *Manager) installNoTrackRules(addr netip.Addr, port uint16) error {
	// Do not install per endpoint NOTRACK rules if we are already skipping
	// conntrack for all pod traffic.
	if m.skipPodTrafficConntrack(addr) {
		return nil
	}

	prog := ip4tables
	if addr.Is6() {
		prog = ip6tables
	}
	for _, p := range noTrackPorts(port) {
		if err := m.endpointNoTrackRules(prog, "-A", addr.String(), p); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) removeNoTrackRules(addr netip.Addr, port uint16) error {
	// Do not remove per endpoint NOTRACK rules if we are already skipping
	// conntrack for all pod traffic.
	if m.skipPodTrafficConntrack(addr) {
		return nil
	}

	prog := ip4tables
	if addr.Is6() {
		prog = ip6tables
	}
	for _, p := range noTrackPorts(port) {
		if err := m.endpointNoTrackRules(prog, "-D", addr.String(), p); err != nil {
			return err
		}
	}
	return nil
}

// skipPodTrafficConntrack returns true if it's possible to install iptables
// `-j CT --notrack` rules to skip tracking pod traffic.
func (m *Manager) skipPodTrafficConntrack(addr netip.Addr) bool {
	if addr.Is4() && m.sharedCfg.InstallNoConntrackIptRules {
		return true
	}
	return false
}

func (m *Manager) addNoTrackPodTrafficRules(prog runnable, podsCIDR string) error {
	for _, chain := range []string{ciliumPreRawChain, ciliumOutputRawChain} {
		if err := prog.runProg([]string{
			"-t", "raw",
			"-I", chain,
			"-s", podsCIDR,
			"-m", "comment", "--comment", "cilium: NOTRACK for pod traffic",
			"-j", "CT", "--notrack"}); err != nil {
			return err
		}

		if err := prog.runProg([]string{
			"-t", "raw",
			"-I", chain,
			"-d", podsCIDR,
			"-m", "comment", "--comment", "cilium: NOTRACK for pod traffic",
			"-j", "CT", "--notrack"}); err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) addCiliumENIRules() error {
	if !m.sharedCfg.EnableIPv4 {
		return nil
	}

	iface, err := route.NodeDeviceWithDefaultRoute(m.sharedCfg.EnableIPv4, m.sharedCfg.EnableIPv6)
	if err != nil {
		return fmt.Errorf("failed to find interface with default route: %w", err)
	}

	nfmask := fmt.Sprintf("%#08x", linux_defaults.MarkMultinodeNodeport)
	ctmask := fmt.Sprintf("%#08x", linux_defaults.MaskMultinodeNodeport)

	// Note: these rules need the xt_connmark module (iptables usually
	// loads it when required, unless loading modules after boot has been
	// disabled).
	if err := ip4tables.runProg([]string{
		"-t", "mangle",
		"-A", ciliumPreMangleChain,
		"-i", iface.Attrs().Name,
		"-m", "comment", "--comment", "cilium: primary ENI",
		"-m", "addrtype", "--dst-type", "LOCAL", "--limit-iface-in",
		"-j", "CONNMARK", "--set-xmark", nfmask + "/" + ctmask}); err != nil {
		return err
	}

	return ip4tables.runProg([]string{
		"-t", "mangle",
		"-A", ciliumPreMangleChain,
		"-i", "lxc+",
		"-m", "comment", "--comment", "cilium: primary ENI",
		"-j", "CONNMARK", "--restore-mark", "--nfmask", nfmask, "--ctmask", ctmask})
}
