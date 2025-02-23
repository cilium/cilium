// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/mountinfo"
)

// BugtoolConfiguration creates and loads the configuration file used to run
// the commands. The only commands not managed by the configuration is initial
// setup, for ex. searching for Cilium daemonset pods or running uname.
type BugtoolConfiguration struct {
	// Commands is the exact commands that will be run by the bugtool
	Commands []string `json:"commands"`
}

func bpffsMountpoint() string {
	mountInfos, err := mountinfo.GetMountInfo()
	if err != nil {
		return ""
	}

	// To determine the mountpoint of the BPF fs we iterate through the list
	// of mount info (i.e. /proc/self/mounts entries) and return the first
	// one which has the "bpf" fs type and the "/" root.
	//
	// The root == "/" condition allows us to ignore all BPF fs which are
	// sub mounts (such as for example /sys/fs/bpf/{xdp, ip, sk, sa}) of the
	// one with the "/" root.
	//
	// Moreover, as Cilium will refuse to start if there are multiple BPF fs
	// which have "/" as their root, we can assume there will be at most one
	// mountpoint which matches the conditions and so we return it as soon
	// as we find it.
	for _, mountInfo := range mountInfos {
		if mountInfo.FilesystemType == "bpf" && mountInfo.Root == "/" {
			return mountInfo.MountPoint
		}
	}

	return ""
}

func cgroup2fsMounts() []string {
	var mounts []string
	mnts, err := mountinfo.GetMountInfo()
	if err != nil {
		return mounts
	}

	// Cgroup2 fs can be mounted at multiple mount points. Ideally, we would
	// like to read the mount point where Cilium attaches BPF cgroup programs
	// (determined by cgroup-root config option). But since this is debug information,
	// let's collect all the mount points.
	for _, mnt := range mnts {
		if mnt.FilesystemType == "cgroup2" {
			mounts = append(mounts, mnt.MountPoint)
		}
	}

	return mounts
}

// LB and CT map for debugging services; using bpftool for a reliable dump
var bpfMapsPath = []string{
	"tc/globals/cilium_auth_map",
	"tc/globals/cilium_call_policy",
	"tc/globals/cilium_calls_overlay_2",
	"tc/globals/cilium_calls_wireguard_2",
	"tc/globals/cilium_calls_xdp",
	"tc/globals/cilium_capture_cache",
	"tc/globals/cilium_runtime_config",
	"tc/globals/cilium_lxc",
	"tc/globals/cilium_metrics",
	"tc/globals/cilium_tunnel_map",
	"tc/globals/cilium_ktime_cache",
	"tc/globals/cilium_ipcache",
	"tc/globals/cilium_ipcache_v2",
	"tc/globals/cilium_events",
	"tc/globals/cilium_signals",
	"tc/globals/cilium_capture4_rules",
	"tc/globals/cilium_capture6_rules",
	"tc/globals/cilium_nodeport_neigh4",
	"tc/globals/cilium_nodeport_neigh6",
	"tc/globals/cilium_node_map",
	"tc/globals/cilium_node_map_v2",
	"tc/globals/cilium_lb4_source_range",
	"tc/globals/cilium_lb6_source_range",
	"tc/globals/cilium_lb4_maglev",
	"tc/globals/cilium_lb6_maglev",
	"tc/globals/cilium_lb6_health",
	"tc/globals/cilium_lb6_reverse_sk",
	"tc/globals/cilium_lb4_health",
	"tc/globals/cilium_lb4_reverse_sk",
	"tc/globals/cilium_ipmasq_v4",
	"tc/globals/cilium_ipmasq_v6",
	"tc/globals/cilium_ipv4_frag_datagrams",
	"tc/globals/cilium_throttle",
	"tc/globals/cilium_encrypt_state",
	"tc/globals/cilium_egress_gw_policy_v4",
	"tc/globals/cilium_srv6_vrf_v4",
	"tc/globals/cilium_srv6_vrf_v6",
	"tc/globals/cilium_srv6_policy_v4",
	"tc/globals/cilium_srv6_policy_v6",
	"tc/globals/cilium_srv6_sid",
	"tc/globals/cilium_lb4_services_v2",
	"tc/globals/cilium_lb4_backends_v2",
	"tc/globals/cilium_lb4_backends_v3",
	"tc/globals/cilium_lb4_backends",
	"tc/globals/cilium_lb4_reverse_nat",
	"tc/globals/cilium_ct4_global",
	"tc/globals/cilium_ct_any4_global",
	"tc/globals/cilium_lb4_affinity",
	"tc/globals/cilium_lb6_affinity",
	"tc/globals/cilium_lb_affinity_match",
	"tc/globals/cilium_lb6_services_v2",
	"tc/globals/cilium_lb6_backends_v2",
	"tc/globals/cilium_lb6_backends_v3",
	"tc/globals/cilium_lb6_backends",
	"tc/globals/cilium_lb6_reverse_nat",
	"tc/globals/cilium_ct6_global",
	"tc/globals/cilium_ct_any6_global",
	"tc/globals/cilium_snat_v4_external",
	"tc/globals/cilium_snat_v6_external",
	"tc/globals/cilium_vtep_map",
	"tc/globals/cilium_l2_responder_v4",
	"tc/globals/cilium_ratelimit",
	"tc/globals/cilium_ratelimit_metrics",
	"tc/globals/cilium_skip_lb4",
	"tc/globals/cilium_skip_lb6",
}

func defaultCommands(confDir string, cmdDir string) []string {
	var commands []string
	// Not expecting all of the commands to be available
	commands = append(commands, miscSystemCommands()...)

	commands = append(commands, bpfMapDumpCommands(bpfMapsPath)...)
	commands = append(commands, bpfCgroupCommands()...)

	// Commands that require variables and / or more configuration are added
	// separately below
	commands = append(commands, catCommands()...)
	commands = append(commands, routeCommands()...)
	commands = append(commands, ethtoolCommands()...)
	commands = append(commands, copyConfigCommands(confDir)...)
	commands = append(commands, ciliumDbgCommands(cmdDir)...)
	commands = append(commands, ciliumHealthCommands()...)
	commands = append(commands, copyStateDirCommand(cmdDir)...)
	commands = append(commands, tcInterfaceCommands()...)

	// We want to collect this twice: at the very beginning and at the
	// very end of the bugtool collection, to see if the counters are
	// increasing.
	// The commands end up being the names of the files where their output
	// is stored, so we can't have the two commands be the exact same or the
	// second would overwrite. To avoid that, we use the -u flag in this second
	// command; that flag is documented as being ignored.
	commands = append(commands, "cat -u /proc/net/xfrm_stat")

	return commands
}

func miscSystemCommands() []string {
	return []string{
		// We want to collect this twice: at the very beginning and at the
		// very end of the bugtool collection, to see if the counters are
		// increasing.
		"cat /proc/net/xfrm_stat",
		// Host and misc
		"ps auxfw",
		"hostname",
		"ip a",
		"ip -4 r",
		"ip -6 r",
		"ip -d -s l",
		"ip -4 n",
		"ip -6 n",
		"ss -t -p -a -i -s -n -e",
		"ss -u -p -a -i -s -n -e",
		"uname -a",
		"top -b -n 1",
		"uptime",
		"dmesg --time-format=iso",
		"sysctl -a",
		"bpftool map show",
		"bpftool prog show",
		"bpftool net show",
		"taskset -pc 1",
		// iptables
		"iptables-save -c",
		"ip6tables-save -c",
		"iptables-nft-save -c",
		"ip6tables-nft-save -c",
		"iptables-legacy-save -c",
		"ip6tables-legacy-save -c",
		"ip -d rule",
		"ipset list",
		// xfrm
		"ip -s xfrm policy",
		"ip -s xfrm state",
		// gops
		fmt.Sprintf("gops memstats $(pidof %s)", components.CiliumAgentName),
		fmt.Sprintf("gops stack $(pidof %s)", components.CiliumAgentName),
		fmt.Sprintf("gops stats $(pidof %s)", components.CiliumAgentName),
		// Get list of open file descriptors managed by the agent
		fmt.Sprintf("ls -la /proc/$(pidof %s)/fd", components.CiliumAgentName),
		"lsmod",
		// tc
		"tc qdisc show",
		"tc -d -s qdisc show", // Show statistics on queuing disciplines
	}
}

func bpfCgroupCommands() []string {
	cgroup2fsMounts := cgroup2fsMounts()

	commands := []string{}

	for i := range cgroup2fsMounts {
		commands = append(commands, []string{
			fmt.Sprintf("bpftool cgroup tree %s", cgroup2fsMounts[i]),
		}...)
	}

	return commands
}

func bpfMapDumpCommands(mapPaths []string) []string {
	bpffsMountpoint := bpffsMountpoint()
	if bpffsMountpoint == "" {
		return nil
	}

	commands := make([]string, 0, len(mapPaths))
	for _, mapPath := range mapPaths {
		commands = append(commands, "bpftool map dump pinned "+filepath.Join(bpffsMountpoint, mapPath))
	}

	return commands
}

func save(c *BugtoolConfiguration, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("Failed to open file %s for writing: %w", path, err)
	}
	defer f.Close()

	data, err := json.MarshalIndent(c, "", "\t")
	if err != nil {
		return fmt.Errorf("Cannot marshal config: %w", err)
	}
	err = os.WriteFile(path, data, 0644)
	if err != nil {
		return fmt.Errorf("Cannot write config: %w", err)
	}
	return nil
}

func loadConfigFile(path string) (*BugtoolConfiguration, error) {
	var content []byte
	var err error
	content, err = os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var c BugtoolConfiguration
	err = json.Unmarshal(content, &c)
	return &c, err
}

// Listing tc filter/chain/classes requires specific interface names.
// Commands are generated per-interface.
func tcInterfaceCommands() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate per interface tc commands: %s\n", fmt.Errorf("could not list network interfaces: %w", err))
		return nil
	}
	commands := []string{}
	for _, iface := range ifaces {
		commands = append(commands,
			fmt.Sprintf("tc filter show dev %s ingress", iface.Name),
			fmt.Sprintf("tc filter show dev %s egress", iface.Name),
			fmt.Sprintf("tc chain show dev %s", iface.Name),
			fmt.Sprintf("tc class show dev %s", iface.Name))
	}
	return commands
}

func catCommands() []string {
	files := []string{
		"/proc/sys/net/core/bpf_jit_enable",
		"/proc/kallsyms",
		"/proc/buddyinfo",
		"/proc/pagetypeinfo",
		"/etc/resolv.conf",
		"/var/log/docker.log",
		"/var/log/daemon.log",
		"/var/log/messages",
		"/var/run/cilium/cilium-cni.log",
		"/proc/sys/kernel/random/boot_id",
	}
	// Only print the files that do exist to reduce number of errors in
	// archive
	commands := []string{}
	for _, f := range files {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			continue
		}
		commands = append(commands, fmt.Sprintf("cat %s", f))
	}

	return commands
}

// routeCommands gets the routes tables dynamically.
func routeCommands() []string {
	commands := []string{}
	routes, _ := execCommand("ip route show table all | grep -E --only-matching 'table [0-9]+'")

	for _, r := range bytes.Split(bytes.TrimSuffix(routes, []byte("\n")), []byte("\n")) {
		routeTablev4 := fmt.Sprintf("ip -4 route show %s", r)
		routeTablev6 := fmt.Sprintf("ip -6 route show %s", r)
		commands = append(commands, routeTablev4, routeTablev6)
	}
	return commands
}

func copyConfigCommands(confDir string) []string {
	commands := []string{}
	// Location is a convenience structure to avoid too many long lines
	type Location struct {
		Src string
		Dst string
	}

	// These locations don't depend on the kernel version for running so we
	// can add them in this scope.
	locations := []Location{
		{"/proc/config", fmt.Sprintf("%s/kernel-config", confDir)},
		{"/proc/config.gz", fmt.Sprintf("%s/kernel-config.gz", confDir)},
	}

	// The following lines copy the kernel configuration.
	kernel, _ := execCommand("uname -r")
	kernel = bytes.TrimSpace(kernel)
	// Append the boot config for the current kernel
	l := Location{
		fmt.Sprintf("/boot/config-%s", kernel),
		fmt.Sprintf("%s/kernel-config-%s", confDir, kernel),
	}
	locations = append(locations, l)

	// Use the locations to create command strings
	for _, location := range locations {
		if _, err := os.Stat(location.Src); os.IsNotExist(err) {
			continue
		}
		commands = append(commands, fmt.Sprintf("cp %s %s", location.Src, location.Dst))
	}

	return commands
}

func ciliumDbgCommands(cmdDir string) []string {
	ciliumDbgCommands := []string{
		fmt.Sprintf("cilium-dbg debuginfo --output=markdown,json -f --output-directory=%s", cmdDir),
		"cilium-dbg metrics list",
		"cilium-dbg shell -- metrics/html",
		"cilium-dbg bpf metrics list",
		"cilium-dbg fqdn cache list",
		"cilium-dbg config -a",
		"cilium-dbg encrypt status",
		"cilium-dbg endpoint list",
		"cilium-dbg bpf auth list",
		"cilium-dbg bpf bandwidth list",
		"cilium-dbg bpf config list",
		"cilium-dbg bpf tunnel list",
		"cilium-dbg bpf lb list",
		"cilium-dbg bpf lb list --revnat",
		"cilium-dbg bpf lb list --frontends",
		"cilium-dbg bpf lb list --backends",
		"cilium-dbg bpf lb list --source-ranges",
		"cilium-dbg bpf lb maglev list",
		"cilium-dbg bpf egress list",
		"cilium-dbg bpf vtep list",
		"cilium-dbg bpf endpoint list",
		"cilium-dbg bpf ct list global",
		"cilium-dbg bpf nat list",
		"cilium-dbg bpf nat retries list",
		"cilium-dbg bpf ipmasq list",
		"cilium-dbg bpf ipcache list",
		"cilium-dbg bpf policy get --all --numeric",
		"cilium-dbg bpf sha list",
		"cilium-dbg bpf fs show",
		"cilium-dbg bpf recorder list",
		"cilium-dbg ip list -n -o json",
		"cilium-dbg map list --verbose",
		"cilium-dbg map events cilium_ipcache -o json",
		"cilium-dbg map events cilium_tunnel_map -o json",
		"cilium-dbg map events cilium_lb4_services_v2 -o json",
		"cilium-dbg map events cilium_lb4_backends_v2 -o json",
		"cilium-dbg map events cilium_lb4_backends_v3 -o json",
		"cilium-dbg map events cilium_lb6_services_v2 -o json",
		"cilium-dbg map events cilium_lb6_backends_v2 -o json",
		"cilium-dbg map events cilium_lb6_backends_v3 -o json",
		"cilium-dbg map events cilium_lxc -o json",
		"cilium-dbg service list",
		"cilium-dbg service list -o json",
		"cilium-dbg recorder list",
		"cilium-dbg status --verbose",
		"cilium-dbg identity list",
		"cilium-dbg policy get",
		"cilium-dbg policy selectors -o json",
		"cilium-dbg node list",
		"cilium-dbg node list -o json",
		"cilium-dbg bpf nodeid list",
		"cilium-dbg lrp list",
		"cilium-dbg cgroups list -o json",
		"cilium-dbg statedb dump",
		"cilium-dbg bgp peers",
		"cilium-dbg bgp routes available ipv4 unicast",
		"cilium-dbg bgp routes available ipv6 unicast",
		"cilium-dbg bgp routes advertised ipv4 unicast",
		"cilium-dbg bgp routes advertised ipv6 unicast",
		"cilium-dbg bgp route-policies",
		"cilium-dbg troubleshoot kvstore",
		"cilium-dbg troubleshoot clustermesh",
		"cilium-dbg bpf frag list",
	}

	if len(host) == 0 {
		return ciliumDbgCommands
	}

	// Add the host flag if set
	return withHostFlag(ciliumDbgCommands)
}

func ciliumHealthCommands() []string {
	ciliumHealthCommands := []string{
		"cilium-health status --verbose",
		"cilium-health status -o json",
	}

	if len(host) == 0 {
		return ciliumHealthCommands
	}

	// Add the host flag if set
	return withHostFlag(ciliumHealthCommands)
}

func withHostFlag(cmds []string) []string {
	var commands []string

	for _, cmd := range cmds {
		commands = append(commands, fmt.Sprintf("%s -H %s", cmd, host))
	}

	return commands
}

func copyStateDirCommand(cmdDir string) []string {
	stateDir := filepath.Join(defaults.RuntimePath, defaults.StateDir)

	dst := filepath.Join(cmdDir, defaults.StateDir)
	return []string{fmt.Sprintf("cp -r %s %s", stateDir, dst)}
}
