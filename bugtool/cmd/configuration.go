// Copyright 2017-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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

func setupDefaultConfig(path string, k8sPods []string, confDir, cmdDir string) (*BugtoolConfiguration, error) {
	c := BugtoolConfiguration{defaultCommands(confDir, cmdDir, k8sPods)}
	return &c, save(&c, path)
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

func defaultCommands(confDir string, cmdDir string, k8sPods []string) []string {
	var commands []string
	// Not expecting all of the commands to be available
	commands = []string{
		// Host and misc
		"ps auxfw",
		"hostname",
		"ip a",
		"ip -4 r",
		"ip -6 r",
		"ip -d -s l",
		"ip -4 n",
		"ip -6 n",
		"ss -t -p -a -i -s",
		"ss -u -p -a -i -s",
		"tc qdisc show",
		"tc -d -s qdisc show",
		"uname -a",
		"top -b -n 1",
		"uptime",
		"dmesg --time-format=iso",
		"sysctl -a",
		"bpftool map show",
		"bpftool prog show",
		// iptables
		"iptables-save -c",
		"iptables -S",
		"ip6tables -S",
		"iptables -L -v",
		"ip rule",
		"ip -4 route show table 2005",
		"ip -6 route show table 2005",
		"ip -4 route show table 200",
		"ip -6 route show table 200",
		// xfrm
		"ip xfrm policy",
		"ip -s xfrm state | awk '!/auth|enc|aead|auth-trunc|comp/'",
		// gops
		fmt.Sprintf("gops memstats $(pidof %s)", components.CiliumAgentName),
		fmt.Sprintf("gops stack $(pidof %s)", components.CiliumAgentName),
		fmt.Sprintf("gops stats $(pidof %s)", components.CiliumAgentName),
		// Get list of open file descriptors managed by the agent
		fmt.Sprintf("ls -la /proc/$(pidof %s)/fd", components.CiliumAgentName),
		"lsmod",
	}

	if bpffsMountpoint := bpffsMountpoint(); bpffsMountpoint != "" {
		commands = append(commands, []string{
			// LB and CT map for debugging services; using bpftool for a reliable dump
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_lb4_services_v2", bpffsMountpoint),
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_lb4_services", bpffsMountpoint),
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_lb4_backends", bpffsMountpoint),
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_lb4_reverse_nat", bpffsMountpoint),
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_ct4_global", bpffsMountpoint),
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_ct_any4_global", bpffsMountpoint),
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_lb4_affinity", bpffsMountpoint),
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_lb6_affinity", bpffsMountpoint),
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_lb_affinity_match", bpffsMountpoint),
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_lb6_services_v2", bpffsMountpoint),
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_lb6_services", bpffsMountpoint),
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_lb6_backends", bpffsMountpoint),
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_lb6_reverse_nat", bpffsMountpoint),
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_ct6_global", bpffsMountpoint),
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_ct_any6_global", bpffsMountpoint),
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_snat_v4_external", bpffsMountpoint),
			fmt.Sprintf("bpftool map dump pinned %s/tc/globals/cilium_snat_v6_external", bpffsMountpoint),
		}...)
	}

	// Commands that require variables and / or more configuration are added
	// separately below
	commands = append(commands, catCommands()...)
	commands = append(commands, ethoolCommands()...)
	commands = append(commands, copyConfigCommands(confDir, k8sPods)...)
	commands = append(commands, copyCiliumInfoCommands(cmdDir, k8sPods)...)

	return k8sCommands(commands, k8sPods)
}

func save(c *BugtoolConfiguration, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("Failed to open file %s for writing: %s", path, err)
	}
	defer f.Close()

	data, err := json.MarshalIndent(c, "", "\t")
	if err != nil {
		return fmt.Errorf("Cannot marshal config %s", err)
	}
	err = ioutil.WriteFile(path, data, 0644)
	if err != nil {
		return fmt.Errorf("Cannot write config %s", err)
	}
	return nil
}

func loadConfigFile(path string) (*BugtoolConfiguration, error) {
	var content []byte
	var err error
	content, err = ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	var c BugtoolConfiguration
	err = json.Unmarshal(content, &c)
	return &c, err
}

func catCommands() []string {
	files := []string{
		"/proc/net/xfrm_stat",
		"/proc/sys/net/core/bpf_jit_enable",
		"/proc/kallsyms",
		"/etc/resolv.conf",
		"/var/log/docker.log",
		"/var/log/daemon.log",
		"/var/log/messages",
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
		kernel = strings.TrimSpace(kernel)
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
			kernel = strings.TrimSpace(kernel)
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

func copyCiliumInfoCommands(cmdDir string, k8sPods []string) []string {
	// Most of the output should come via debuginfo but also adding
	// these ones for skimming purposes
	ciliumCommands := []string{
		fmt.Sprintf("cilium debuginfo --output=markdown,json -f --output-directory=%s", cmdDir),
		"cilium metrics list",
		"cilium fqdn cache list",
		"cilium config",
		"cilium bpf bandwidth list",
		"cilium bpf tunnel list",
		"cilium bpf lb list",
		"cilium bpf endpoint list",
		"cilium bpf ct list global",
		"cilium bpf nat list",
		"cilium bpf ipmasq list",
		"cilium bpf ipcache list",
		"cilium bpf policy get --all --numeric",
		"cilium bpf sha list",
		"cilium bpf fs show",
		"cilium ip list -n -o json",
		"cilium map list --verbose",
		"cilium service list",
		"cilium status --verbose",
		"cilium identity list",
		"cilium-health status",
		"cilium policy selectors -o json",
		"cilium node list",
	}
	var commands []string

	stateDir := filepath.Join(defaults.RuntimePath, defaults.StateDir)
	if len(k8sPods) == 0 { // Assuming this is a non k8s deployment
		dst := filepath.Join(cmdDir, defaults.StateDir)
		commands = append(commands, fmt.Sprintf("cp -r %s %s", stateDir, dst))
		for _, cmd := range ciliumCommands {
			// Add the host flag if set
			if len(host) > 0 {
				cmd = fmt.Sprintf("%s -H %s", cmd, host)
			}
			commands = append(commands, cmd)
		}
	} else { // Found k8s pods
		for _, pod := range k8sPods {
			dst := filepath.Join(cmdDir, fmt.Sprintf("%s-%s", pod, defaults.StateDir))
			kubectlArg := fmt.Sprintf("%s/%s:%s", k8sNamespace, pod, stateDir)
			// kubectl cp kube-system/cilium-xrzwr:/var/run/cilium/state cilium-xrzwr-state
			commands = append(commands, fmt.Sprintf("kubectl cp %s %s", kubectlArg, dst))
			for _, cmd := range ciliumCommands {
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

func k8sCommands(allCommands []string, pods []string) []string {
	// These commands do not require a pod argument
	var commands = []string{
		"kubectl get nodes -o wide",
		"kubectl describe nodes",
		"kubectl get pods,svc --all-namespaces",
		"kubectl version",
		fmt.Sprintf("kubectl get cm cilium-config -n %s", k8sNamespace),
	}

	// Prepare to run all the commands inside of the pod(s)
	for _, pod := range pods {
		for _, cmd := range allCommands {
			// Add the host flag if set
			if strings.HasPrefix(cmd, "cilium") &&
				!strings.Contains(cmd, "-H") && len(host) > 0 {
				cmd = fmt.Sprintf("%s -H %s", cmd, host)
			}

			if !strings.Contains(cmd, "kubectl exec") {
				cmd = podPrefix(pod, cmd)
			}
			commands = append(commands, cmd)
		}

		// Retrieve current version of pod logs
		cmd := fmt.Sprintf("kubectl -n %s logs --timestamps %s", k8sNamespace, pod)
		commands = append(commands, cmd)

		// Retrieve previous version of pod logs
		cmd = fmt.Sprintf("kubectl -n %s logs --timestamps -p %s", k8sNamespace, pod)
		commands = append(commands, cmd)

		cmd = fmt.Sprintf("kubectl -n %s describe pod %s", k8sNamespace, pod)
		commands = append(commands, cmd)
	}

	if len(pods) == 0 {
		allCommands = append(allCommands, commands...)
		return allCommands
	}

	return commands
}
