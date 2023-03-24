// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package configuration

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/cilium/cilium/bugtool/dump"
	"github.com/cilium/cilium/bugtool/options"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/mountinfo"

	log "github.com/sirupsen/logrus"
)

func deduplicate(arr []string) []string {
	sort.Strings(arr)
	if len(arr) <= 1 {
		return arr
	}
	narr := []string{arr[0]}
	for i := 1; i < len(arr); i++ {
		if arr[i] != arr[i-1] {
			narr = append(narr, arr[i])
		}
	}
	return narr
}

// CreateDump creates the root dump task to be used for bugtool dumps.
// If a configuration file is specified, it will attempt to use that
// to load a task, otherwise it uses the "topics" list to compose a
// a task.
func CreateDump(conf *options.Config) dump.Task {
	if conf.ConfigFile != "" && !(conf.Generate || conf.DryRun) {
		log.Infof("Using specified config file: %s", conf.ConfigFile)
		fd, err := os.Open(conf.ConfigFile)
		if err != nil {
			log.Fatalf("Failed to open config file %s: %v", conf.ConfigFile, err)
		}
		t, err := dump.Decode(fd)
		if err != nil {
			log.Fatalf("Failed to decode config %s: %v", conf.ConfigFile, err)
		}
		return t
	}

	// Handle deprecated topic specific flags.
	if conf.EnvoyDump {
		conf.Topics = append(conf.Topics, "envoy")
	}

	if conf.GetPProf {
		log.Info("[Deprecated] Use --topics=pprof instead")
		conf.Topics = append(conf.Topics, "pprof")
	}

	ts := dump.Tasks{}
	conf.Topics = deduplicate(conf.Topics)
	log.Debugf("Final topics list %v", conf.Topics)
	for _, topic := range conf.Topics {
		switch topic {
		// Bpfmaps contains dump tasks for dumping Cilium bpf maps,
		// as well as a list of bpf maps/attachments/programs.
		//
		// Anything dumped with 'bpftool' should go in here.
		case "bpfmaps":
			// bpfmaps is a dump of Cilium related bpf maps.
			ts = append(ts,
				dump.NewDir("bpfmaps", GenerateBPFToolTasks()),
			)

		// Agent contains output from cilium agent commands (i.e. cilium agent API).
		// It also includes state data.
		//
		// Anything dumped with the Pods "cilium ..." command belongs in here.
		case "agent":
			// agent is dumps of data gathered directly from the
			// Cilium Agent.
			ts = append(ts,
				dump.NewDir("agent", CiliumTasks()),
			)
			fallthrough

		// State contains cilium runtime state that is written to disk,
		// including endpoint restore data.
		// This is also included as part of the "agent" topic.
		case "state":
			runFiles := dump.NewFile("/run/cilium/state")
			if conf.ExcludeObjectFiles {
				runFiles = runFiles.WithExclude(defaults.StateDir + "/[0-9]*/*.o")
			}
			ts = append(ts, dump.NewDir("state", dump.Tasks{runFiles}))

		// System includes output to host system commands and configurations.
		// Command output is organized by structured/unstructured for commands
		// that has a easily parsable output (i.e. JSON, YAML) and anything else.
		case "system":
			logs, unstructured, structured := defaultResources()
			// system contains system level dumps.
			ts = append(ts, dump.NewDir("system", dump.Tasks{
				dump.NewDir("structured", structured),
				dump.NewDir("unstructured", unstructured),
				dump.NewDir("logs", logs),
				dump.NewDir("files", systemFileDumps()),
			}))
		// Envoy contains dumps for Cilium Envoy specific configuration.
		// This connects to Envoy on its local API unix socket and requests
		// current Envoy configuration state.
		case "envoy":
			ts = append(ts, dump.NewDir("envoy", getEnvoyDump()))

		// PProf attempts to run pprof profile commands.
		case "pprof":
			ts = append(ts, dump.NewDir("pprof", GetPProf(conf)))

		// Gops runs gops runtime for diagnostics such as:
		// * Goroutine stack trace (useful for diagnosing deadlocks).
		// * Runtime/Memory stats.
		case "gops":
			ts = append(ts, dump.NewDir("gops", gopsCommands()))
		default:
			log.Fatalf("unexpected topic %q", topic)
		}
	}
	return dump.NewDir("", ts)
}

func defaultResources() (logs, unstructured, structured dump.Tasks) {
	for _, cmd := range unstructuredCommands() {
		unstructured = append(unstructured, createExecFromString(cmd, "txt"))
	}

	for _, cmd := range jsonStructuredCommands() {
		structured = append(structured, createExecFromString(cmd, "json"))
	}

	xfrmState := createExecFromString("ip --json -s xfrm state", "json")
	xfrmState.HashEncryptionKeys = true
	structured = append(structured, xfrmState)

	for _, cmd := range logCommands() {
		logs = append(logs, createExecFromString(cmd, "log"))
	}

	structured = append(structured, routeCommands()...)
	return
}

// unstructuredCommands returns all default system commands (excluding bpf related ones...) to
// be converted to dump.Tasks.
func unstructuredCommands() []string {
	var commands []string
	generators := []func() []string{
		humanReadableCommands,
		tableStructuredCommands,
		bpftoolCGroupTreeCommands,
		tcInterfaceCommands,
	}

	for _, generator := range generators {
		commands = append(commands, generator()...)
	}

	return commands
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

func bpftoolCGroupTreeCommands() []string {
	cgroup2fsMounts := cgroup2fsMounts()
	commands := []string{}
	for i := range cgroup2fsMounts {
		commands = append(commands, fmt.Sprintf("bpftool cgroup tree %s", cgroup2fsMounts[i]))
	}
	return commands
}

// GenerateTaskName tries to do a reasonable job of converting
// a raw command string to a legible task name.
func GenerateTaskName(cmdStr string) string {
	toks := strings.Fields(cmdStr)
	name := ""
	for i := 0; i < len(toks); i++ {
		tok := toks[i]
		tok = strings.ReplaceAll(tok, "/", "_")
		switch tok {
		case "--output", "-o":
			i++
			continue
		default:
			if strings.HasPrefix(tok, "-") {
				continue
			}
			if name == "" {
				name = tok
			} else {
				if strings.HasPrefix(tok, "_") {
					name += tok
				} else {
					name += "-" + tok
				}
			}
		}
	}
	return name
}

func createExecFromString(cmdStr, ext string) *dump.Exec {
	if cmdStr == "" {
		log.Fatalf("could not parse task, cmd string %q cannot be empty", cmdStr)
	}
	toks := strings.Fields(cmdStr)
	name := GenerateTaskName(cmdStr)
	return dump.NewExec(name, ext, toks[0], toks[1:]...)
}

// Listing tc filter/chain/classes requires specific interface names.
// Commands are generated per-interface.
func tcInterfaceCommands() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate per interface tc commands: %s\n", err)
		return nil
	}
	commands := []string{}
	for _, iface := range ifaces {
		commands = append(commands,
			fmt.Sprintf("tc filter show dev %s ingress", iface.Name),
			fmt.Sprintf("tc filter show dev %s egress", iface.Name),
			fmt.Sprintf("tc chain show dev %s", iface.Name),
			fmt.Sprintf("tc class show dev %s", iface.Name),
		)
	}
	return commands
}

func systemFileDumps() []dump.Task {
	ts := []dump.Task{}
	files := []string{
		"/proc/net/xfrm_stat",
		"/proc/sys/net/core/bpf_jit_enable",
		"/proc/kallsyms",
		"/etc/resolv.conf",
		"/var/log/docker.log",
		"/var/log/daemon.log",
		"/var/log/messages",
	}
	for _, f := range files {
		ts = append(ts, dump.NewFile(f))
	}
	return ts
}

// routeCommands gets the routes tables dynamically.
func routeCommands() []dump.Task {
	// oneline script gets table names for all devices, then dumps either ip4/ip6 route tables.
	routesScript := "for table in $(ip --json route show table all | jq -r '.[] | select(.table != null) | select(.table != \"local\") | .table'); do ip --json %s route show table $table ; done"
	var commands []dump.Task
	commands = append(commands,
		dump.NewExec("ip4-route-tables", "json", "bash", []string{"-c", fmt.Sprintf(routesScript, "-4")}...),
		dump.NewExec("ip6-route-tables", "json", "bash", []string{"-c", fmt.Sprintf(routesScript, "-6")}...),
	)
	return commands
}

// Returns commands that have bespoke output formatting, designed
// for human readability over machine parsing.
// Note: These are deprecated and are here for legacy reasons.
// Avoid adding commands that cannot be easily parsed by a machine
// (preferably in json).
// If necessary, it may be preferable to write functionality as a bugtool/dump.Task.
func humanReadableCommands() []string {
	return []string{
		"top -b -n 1",
		"uptime",

		// ss
		"ss -H -t -p -a -i -s",

		// ps
		"ps auxfw", // todo: rework this, use go, add ppid

		// iptables
		"iptables-save -c",
		"ip6tables-save -c",
		"iptables-nft-save -c",
		"ip6tables-nft-save -c",
		"iptables-legacy-save -c",
		"ip6tables-legacy-save -c",
		"ipset list",
	}
}

func logCommands() []string {
	return []string{
		"dmesg --time-format=iso",
	}
}

func tableStructuredCommands() []string {
	return []string{
		// Host and misc
		"hostname",
		"uname -a",
		"uptime",
		"sysctl -a",
		"taskset -pc 1",
		"lsmod",

		"ss -H -u -p -a -s",
	}
}

// Contains commands that output json.
func jsonStructuredCommands() []string {
	return []string{
		// ip
		"ip -j a",
		"ip -j -4 r",
		"ip -j -6 r",
		"ip -j -d -s l",
		"ip -j -4 n",
		"ip -j -6 n",

		// tc
		"tc -j -s qdisc show", // Show statistics on queuing disciplines

		// ip
		"ip --json rule",
		// xfrm
		"ip --json -s xfrm policy",
	}
}

// gops is a special case, you can't really format this data but we still need it.
// this should go in its own dir.
func gopsCommands() dump.Tasks {
	addr := "localhost:9890"
	ts := dump.Tasks{}
	for _, c := range []string{"memstats", "stack", "stats"} {
		ts = append(ts,
			createExecFromString(fmt.Sprintf("gops %s %s", c, addr), "md"),
		)
	}
	return ts
}
