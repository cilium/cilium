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
	"strings"

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

func defaultCommands(confDir string, cmdDir string, k8sPods []string) []string {
	var commands []string
	// Not expecting all of the commands to be available
	commands = []string{
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

	// LB and CT map for debugging services; using bpftool for a reliable dump
	bpfMapsPath := []string{
		"tc/globals/cilium_auth_map",
		"tc/globals/cilium_call_policy",
		"tc/globals/cilium_calls_overlay_2",
		"tc/globals/cilium_calls_xdp",
		"tc/globals/cilium_capture_cache",
		"tc/globals/cilium_runtime_config",
		"tc/globals/cilium_lxc",
		"tc/globals/cilium_metrics",
		"tc/globals/cilium_tunnel_map",
		"tc/globals/cilium_ktime_cache",
		"tc/globals/cilium_ipcache",
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
	commands = append(commands, bpfMapDumpCommands(bpfMapsPath)...)

	cgroup2fsMounts := cgroup2fsMounts()
	for i := range cgroup2fsMounts {
		commands = append(commands, []string{
			fmt.Sprintf("bpftool cgroup tree %s", cgroup2fsMounts[i]),
		}...)
	}

	// Commands that require variables and / or more configuration are added
	// separately below
	commands = append(commands, catCommands()...)
	commands = append(commands, routeCommands()...)
	commands = append(commands, ethtoolCommands()...)
	commands = append(commands, copyConfigCommands(confDir, k8sPods)...)
	commands = append(commands, ciliumInfoCommands(cmdDir, k8sPods)...)

	tcCommands, err := tcInterfaceCommands()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate per interface tc commands: %s\n", err)
	} else {
		commands = append(commands, tcCommands...)
	}

	// We want to collect this twice: at the very beginning and at the
	// very end of the bugtool collection, to see if the counters are
	// increasing.
	// The commands end up being the names of the files where their output
	// is stored, so we can't have the two commands be the exact same or the
	// second would overwrite. To avoid that, we use the -u flag in this second
	// command; that flag is documented as being ignored.
	commands = append(commands, "cat -u /proc/net/xfrm_stat")

	return k8sCommands(commands, k8sPods)
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
func tcInterfaceCommands() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("could not list network interfaces: %w", err)
	}
	commands := []string{}
	for _, iface := range ifaces {
		commands = append(commands,
			fmt.Sprintf("tc filter show dev %s ingress", iface.Name),
			fmt.Sprintf("tc filter show dev %s egress", iface.Name),
			fmt.Sprintf("tc chain show dev %s", iface.Name),
			fmt.Sprintf("tc class show dev %s", iface.Name))
	}
	return commands, nil
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
	// TODO: handle K8s case as well.
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

func copyConfigCommands(confDir string, k8sPods []string) []string {
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

	// The following lines copy the kernel configuration. This code is
	// duplicated for the non Kubernetes case. The variables preventing
	// them to be one block is the pod prefix and namespace used in the
	// path. This should be refactored.
	if len(k8sPods) == 0 {
		kernel, _ := execCommand("uname -r")
		kernel = bytes.TrimSpace(kernel)
		// Append the boot config for the current kernel
		l := Location{fmt.Sprintf("/boot/config-%s", kernel),
			fmt.Sprintf("%s/kernel-config-%s", confDir, kernel)}
		locations = append(locations, l)

		// Use the locations to create command strings
		for _, location := range locations {
			if _, err := os.Stat(location.Src); os.IsNotExist(err) {
				continue
			}
			commands = append(commands, fmt.Sprintf("cp %s %s", location.Src, location.Dst))
		}
	} else {
		// If there are multiple pods, we want to get all of the kernel
		// configs. Therefore we need copy commands for all the pods.
		for _, pod := range k8sPods {
			prompt := podPrefix(pod, "uname -r")
			kernel, _ := execCommand(prompt)
			kernel = bytes.TrimSpace(kernel)
			l := Location{fmt.Sprintf("/boot/config-%s", kernel),
				fmt.Sprintf("%s/kernel-config-%s", confDir, kernel)}
			locations = append(locations, l)

			// The location is mostly the same but the command is
			// prepended with 'kubectl` and the path contains the
			// namespace and pod. For ex:
			// kubectl cp kube-system/cilium-kg8lv:/tmp/cilium-bugtool-243785589.tar /tmp/cilium-bugtool-243785589.tar
			for _, location := range locations {
				kubectlArg := fmt.Sprintf("%s/%s:%s", k8sNamespace, pod, location.Src)
				cmd := fmt.Sprintf("%s %s %s %s", "kubectl", "cp", kubectlArg, location.Dst)
				commands = append(commands, cmd)
			}
		}
	}
	return commands
}

func ciliumInfoCommands(cmdDir string, k8sPods []string) []string {
	// Most of the output should come via debuginfo but also adding
	// these ones for skimming purposes
	commands := []string{
		fmt.Sprintf("cilium-dbg debuginfo --output=markdown,json -f --output-directory=%s", cmdDir),
		"cilium-dbg metrics list",
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
		"cilium-dbg-health status --verbose",
		"cilium-dbg-health status -o json",
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
	}

	return append(k8sPerPodCopyCommands(commands, k8sPods), k8sPerPodCopyStateDir(cmdDir, k8sPods)...)
}

func k8sPerPodCopyCommands(infoCommands []string, k8sPods []string) []string {
	var commands []string

	if len(k8sPods) == 0 { // Assuming this is a non k8s deployment
		for _, cmd := range infoCommands {
			// Add the host flag if set
			if len(host) > 0 {
				cmd = fmt.Sprintf("%s -H %s", cmd, host)
			}
			commands = append(commands, cmd)
		}
	} else { // Found k8s pods
		for _, pod := range k8sPods {
			for _, cmd := range infoCommands {
				// Add the host flag if set
				if len(host) > 0 {
					cmd = fmt.Sprintf("%s -H %s", cmd, host)
				}
				commands = append(commands, podPrefix(pod, cmd))
			}
		}
	}

	return commands
}

func k8sPerPodCopyStateDir(cmdDir string, k8sPods []string) []string {
	stateDir := filepath.Join(defaults.RuntimePath, defaults.StateDir)

	if len(k8sPods) == 0 { // Assuming this is a non k8s deployment
		dst := filepath.Join(cmdDir, defaults.StateDir)
		return []string{fmt.Sprintf("cp -r %s %s", stateDir, dst)}
	}

	commands := make([]string, 0, len(k8sPods))

	// Found k8s pods
	for _, pod := range k8sPods {
		dst := filepath.Join(cmdDir, fmt.Sprintf("%s-%s", pod, defaults.StateDir))
		kubectlArg := fmt.Sprintf("-c %s %s/%s:%s", ciliumAgentContainerName, k8sNamespace, pod, stateDir)
		// kubectl cp kube-system/cilium-xrzwr:/var/run/cilium/state cilium-xrzwr-state
		commands = append(commands, fmt.Sprintf("kubectl cp %s %s", kubectlArg, dst))
	}

	return commands
}

func k8sCommands(allCommands []string, pods []string) []string {
	// These commands do not require a pod argument
	var commands = []string{
		"kubectl get nodes -o wide",
		"kubectl describe nodes",
		"kubectl get pods,svc --all-namespaces",
		"kubectl version",
		fmt.Sprintf("kubectl get cm cilium-config -n %s", k8sNamespace),
	}

	if len(pods) == 0 {
		return append(allCommands, commands...)
	}

	commands = append(commands, k8sPerPodCommands(allCommands, pods)...)
	return append(commands, k8sPodInfo(pods)...)
}

func k8sPerPodCommands(allCommands []string, pods []string) []string {
	commands := make([]string, 0, len(pods)*len(allCommands))

	// Prepare to run all the commands inside of the pod(s)
	for _, pod := range pods {
		for _, cmd := range allCommands {
			// Add the host flag if set
			if strings.HasPrefix(cmd, "cilium") &&
				!strings.Contains(cmd, "-H") && len(host) > 0 {
				cmd = fmt.Sprintf("%s -H %s", cmd, host)
			}

			if !strings.Contains(cmd, "kubectl exec") && !strings.Contains(cmd, "kubectl cp") {
				cmd = podPrefix(pod, cmd)
			}
			commands = append(commands, cmd)
		}
	}

	return commands
}

func k8sPodInfo(pods []string) []string {
	// get current logs, previous logs and describe for each pod
	commands := make([]string, 0, len(pods)*3)

	for _, pod := range pods {
		// Retrieve current version of pod logs
		cmd := fmt.Sprintf("kubectl -n %s logs --timestamps %s", k8sNamespace, pod)
		commands = append(commands, cmd)

		// Retrieve previous version of pod logs
		cmd = fmt.Sprintf("kubectl -n %s logs --timestamps -p %s", k8sNamespace, pod)
		commands = append(commands, cmd)

		cmd = fmt.Sprintf("kubectl -n %s describe pod %s", k8sNamespace, pod)
		commands = append(commands, cmd)
	}

	return commands
}
