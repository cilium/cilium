// Copyright 2017 Authors of Cilium
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
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/daemon/defaults"

	"github.com/spf13/cobra"
)

// BugtoolRootCmd is the top level command for the bugtool.
var BugtoolRootCmd = &cobra.Command{
	Use:   "bugtool",
	Short: "Cilium agent debugging tool",
	Long:  "cilium-bugtool - capture system and node information for debugging a Cilium node",
	Run: func(cmd *cobra.Command, args []string) {
		runTool()
	},
}

const (
	disclaimer = `DISCLAIMER
This tool has copied information about your environment.
If you are going to register a issue on GitHub, please
only provide files from the archive you have reviewed
for sensitive information.
`
	// execTimeout is the timeout for any cmd execution
	execTimeout = 5 * time.Second
)

var (
	archive      bool
	k8s          bool
	serve        bool
	port         int
	dumpPath     string
	host         string
	k8sNamespace string
	k8sLabel     string
)

func init() {
	BugtoolRootCmd.Flags().BoolVar(&archive, "archive", true, "Create archive when false skips deletion of the output directory")
	BugtoolRootCmd.Flags().BoolVar(&serve, "serve", false, "Start HTTP server to serve static files")
	BugtoolRootCmd.Flags().BoolVar(&k8s, "k8s-mode", false, "Require Kubernetes pods to be found or fail")
	BugtoolRootCmd.Flags().IntVarP(&port, "port", "p", 4444, "Port to use for the HTTP server, (default 4444)")
	BugtoolRootCmd.Flags().StringVarP(&dumpPath, "tmp", "t", "/tmp", "Path to store extracted files")
	BugtoolRootCmd.Flags().StringVarP(&host, "host", "H", "", "URI to server-side API")
	BugtoolRootCmd.Flags().StringVarP(&k8sNamespace, "k8s-namespace", "", "kube-system", "Kubernetes namespace for Cilium pod")
	BugtoolRootCmd.Flags().StringVarP(&k8sLabel, "k8s-label", "", "k8s-app=cilium", "Kubernetes label for Cilium pod")
}

func getVerifyCiliumPods() []string {
	// By default try to pick either Kubernetes or non-k8s (host mode). If
	// we find Cilium pod(s) then it's k8s-mode otherwise host mode.
	// Passing extra flags can override the default.
	k8sPods, err := getCiliumPods(k8sNamespace, k8sLabel)
	switch {
	case k8s:
		// When the k8s flag is set, perform extra checks that we actually do have pods or fail.
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\nFailed to find pods, is kube-apiserver running?\n", err)
			os.Exit(1)
		}
		if len(k8sPods) < 1 {
			fmt.Fprintf(os.Stderr, "Found no pods, is kube-apiserver running?\n")
			os.Exit(1)
		}
	case os.Getuid() != 0 && len(k8sPods) == 0:
		// When the k8s flag is not set and the user is not root,
		// debuginfo and BPF related commands can fail.
		fmt.Printf("Warning, some of the BPF commands might fail when run as not root\n")
	}

	return k8sPods
}

func runTool() {
	k8sPods := getVerifyCiliumPods()

	defer printDisclaimer()
	// Prevent collision with other directories
	nowStr := time.Now().Format("20060102-150405.999-0700-MST")
	prefix := fmt.Sprintf("cilium-bugtool-%s-", nowStr)
	dbgDir, err := ioutil.TempDir(dumpPath, prefix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create debug directory %s\n", err)
		os.Exit(1)
	}
	defer cleanup(dbgDir)

	copySystemInfo(createDir(dbgDir, "cmd"), k8sPods)
	copyCiliumInfo(createDir(dbgDir, "cilium"), k8sPods)
	copyKernelConfig(createDir(dbgDir, "conf"), k8sPods)

	// Please don't change the output below for the archive or directory.
	// The order matters and is being used by scripts to copy the right
	// file(s).
	if archive {
		archivePath, err := createArchive(dbgDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create archive %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nARCHIVE at %s\n", archivePath)
	} else {
		fmt.Printf("\nDIRECTORY at %s\n", dbgDir)
	}

	if serve {
		// Use signal handler to cleanup after serving
		setupSigHandler(dbgDir)
		serveStaticFiles(dbgDir)
	}
}

func printDisclaimer() {
	fmt.Print(disclaimer)
}

func cleanup(dbgDir string) {
	if !archive {
		// Perserve directory when archive is not created
		return
	}
	if err := os.RemoveAll(dbgDir); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to cleanup temporary files %s\n", err)
	}
}

func setupSigHandler(dbgDir string) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		for range signalChan {
			printDisclaimer()
			cleanup(dbgDir)
			os.Exit(0)
		}
	}()
}

func serveStaticFiles(debugDirectory string) {
	fs := http.FileServer(http.Dir(debugDirectory))
	addr := fmt.Sprintf(":%d", port)

	http.Handle("/", fs)
	fmt.Printf("Serving files at http://localhost%s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Could not start server %s\n", err)
	}
}

func createDir(dbgDir string, newDir string) string {
	confDir := filepath.Join(dbgDir, newDir)
	if err := os.Mkdir(confDir, defaults.RuntimePathRights); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create %s info directory %s\n", newDir, err)
		return dbgDir
	}
	return confDir
}

func copyKernelConfig(confDir string, k8sPods []string) {
	type Location struct {
		Src string
		Dst string
	}

	locations := []Location{
		{"/proc/config", fmt.Sprintf("%s/kernel-config", confDir)},
		{"/proc/config.gz", fmt.Sprintf("%s/kernel-config.gz", confDir)},
	}

	if len(k8sPods) == 0 {
		kernel, _ := execCommand("uname", "-r")
		kernel = strings.TrimSpace(kernel)
		l := Location{fmt.Sprintf("/boot/config-%s", kernel),
			fmt.Sprintf("%s/kernel-config-%s", confDir, kernel)}
		locations = append(locations, l)

		for _, location := range locations {
			if _, err := os.Stat(location.Src); os.IsNotExist(err) {
				continue
			}
			if err := copyFile(location.Src, location.Dst); err != nil {
				fmt.Fprintf(os.Stderr, "Could not copy kernel config %s\n", err)
			}
		}
	} else {
		for _, pod := range k8sPods {
			prompt := podPrefix(pod, "uname -r")
			cmd, args := split(prompt)
			kernel, _ := execCommand(cmd, args...)
			kernel = strings.TrimSpace(kernel)
			l := Location{fmt.Sprintf("/boot/config-%s", kernel),
				fmt.Sprintf("%s/kernel-config-%s", confDir, kernel)}
			locations = append(locations, l)

			for _, location := range locations {
				kubectlArg := fmt.Sprintf("%s/%s:%s", k8sNamespace, pod, location.Src)
				if _, err := execCommand("kubectl", "cp", kubectlArg, location.Dst); err != nil {
					fmt.Fprintf(os.Stderr, "Could not copy kernel config %s\n", err)
				}
			}
		}
	}
}

func copySystemInfo(cmdDir string, k8sPods []string) {
	// Not expecting all of the commands to be available
	commands := []string{
		// Host and misc
		"ps", "hostname", "ip a", "ip r", "ip link", "uname -a",
		"dig", "netstat", "pidstat", "arp", "top -b -n 1", "uptime",
		"dmesg", "bpftool map show", "bpftool prog show",
		// Versions
		"docker version",
		// Docker and Kubernetes logs from systemd
		"journalctl -u cilium*", "journalctl -u kubelet",
	}
	commands = append(commands, catCommands()...)
	commands = append(commands, ethoolCommands()...)
	commands = append(commands, "iptables-save", "iptables -S", "ip6tables -S", "iptables -L -v")

	if len(k8sPods) == 0 {
		runAll(commands, cmdDir, k8sPods)
		return
	}

	// Prepare to run all the commands inside of the pod(s)
	k8sCommands := []string{}
	for _, pod := range k8sPods {
		for _, cmd := range commands {
			// Add the host flag if set
			if len(host) > 0 {
				cmd = fmt.Sprintf("%s -H %s", cmd, host)
			}
			k8sCommands = append(k8sCommands, podPrefix(pod, cmd))
		}

		// Check for previous logs of the pod
		cmd := fmt.Sprintf("kubectl -n %s logs --previous -p %s", k8sNamespace, pod)
		k8sCommands = append(k8sCommands, cmd)
	}
	k8sCommands = append(k8sCommands, "kubectl describe nodes",
		"kubectl version",
		"kubectl -n kube-system get pods",
		"kubectl get pods,svc --all-namespaces",
		"kubectl get version",
	)

	runAll(k8sCommands, cmdDir, k8sPods)
}

func podPrefix(pod, cmd string) string {
	return fmt.Sprintf("kubectl exec %s -n %s -- %s", pod, k8sNamespace, cmd)
}

func runAll(commands []string, cmdDir string, k8sPods []string) {
	numRoutinesAtOnce := len(commands) / 2
	semaphore := make(chan bool, numRoutinesAtOnce)
	for i := 0; i < numRoutinesAtOnce; i++ {
		// This will not block because the channel is buffered and we
		// can write to it numRoutinesAtOnce before the write blocks
		semaphore <- true
	}

	wg := sync.WaitGroup{}
	for _, cmd := range commands {
		if strings.Contains(cmd, "tables") {
			// iptables commands hold locks so we can't have multiple runs. They
			// have to be run one at a time to avoid 'Another app is currently
			// holding the xtables lock...'
			writeCmdToFile(cmdDir, cmd, k8sPods)
			continue
		}
		// Tell the wait group it needs to track another goroutine
		wg.Add(1)

		// Start a subroutine to run our command
		go func(cmd string) {
			// Once we exit this goroutine completely, signal the
			// original that we are done
			defer wg.Done()

			// This will wait until an entry in this channel is
			// available to read. We started with numRoutinesAtOnce
			// in there (from above)
			<-semaphore
			// When we are done we return the thing we took from
			// the semaphore, so another goroutine can get it
			defer func() { semaphore <- true }()
			writeCmdToFile(cmdDir, cmd, k8sPods)
		}(cmd)
	}
	// Wait for all the spawned goroutines to finish up.
	wg.Wait()
}

func catCommands() []string {
	// Only print the files that do exist to reduce number of errors in
	// archive
	commands := []string{}
	files := []string{
		// Look for some configuration
		"/proc/sys/net/core/bpf_jit_enable", "/proc/kallsyms",
		"/etc/resolv.conf",
		// Look for more logs
		"/var/log/upstart/docker.log", "/var/log/docker.log",
		"/var/log/daemon.log", "/var/log/messages",
	}

	for _, f := range files {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			continue
		}
		commands = append(commands, fmt.Sprintf("cat %s", f))
	}
	return commands
}

func copyCiliumInfo(ciliumDir string, k8sPods []string) {
	sources := []string{
		// Most of the output should come via debuginfo but also adding
		// these ones for skimming purposes
		"cilium debuginfo", "cilium config", "cilium bpf tunnel list", "cilium bpf lb list",
		"cilium bpf endpoint list", "cilium bpf ct list global",
	}

	stateDir := filepath.Join(defaults.RuntimePath, defaults.StateDir)
	if len(k8sPods) == 0 { // Assuming this is a non k8s deployment
		dst := filepath.Join(ciliumDir, defaults.StateDir)
		if err := copyDir(stateDir, dst); err != nil {
			fmt.Fprintf(os.Stderr, "Could not copy state directory %s\n", err)
		}

		for _, cmd := range sources {
			// Add the host flag if set
			if len(host) > 0 {
				cmd = fmt.Sprintf("%s -H %s", cmd, host)
			}
			writeCmdToFile(ciliumDir, cmd, k8sPods)
		}
	} else { // Found k8s pods
		for _, pod := range k8sPods {
			dst := filepath.Join(ciliumDir, fmt.Sprintf("%s-%s", pod, defaults.StateDir))
			kubectlArg := fmt.Sprintf("%s/%s:%s", k8sNamespace, pod, stateDir)
			// kubectl cp kube-system/cilium-xrzwr:/var/run/cilium/state cilium-xrzwr-state
			if _, err := execCommand("kubectl", "cp", kubectlArg, dst); err != nil {
				fmt.Fprintf(os.Stderr, "Could not copy state directory %s\n", err)
			}

			for _, cmd := range sources {
				// Add the host flag if set
				if len(host) > 0 {
					cmd = fmt.Sprintf("%s -H %s", cmd, host)
				}
				writeCmdToFile(ciliumDir, podPrefix(pod, cmd), k8sPods)
			}
		}
	}
}

func execCommand(cmd string, args ...string) (string, error) {
	fmt.Printf("exec: %s %s\n", cmd, args)
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, cmd, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("exec timeout")
	}
	return string(output), err
}

// writeCmdToFile will execute command and write markdown output to a file
func writeCmdToFile(cmdDir, prompt string, k8sPods []string) {
	// Clean up the filename
	name := strings.Replace(prompt, "/", " ", -1)
	name = strings.Replace(name, " ", "-", -1)
	f, err := os.Create(filepath.Join(cmdDir, name+".md"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create file %s\n", err)
		return
	}
	defer f.Close()

	cmd, args := split(prompt)

	if len(k8sPods) == 0 {
		// The command does not exist, abort.
		if _, err := exec.LookPath(cmd); err != nil {
			os.Remove(f.Name())
			return
		}
	} else if len(args) > 5 {
		// Boundary check is necessary to skip other non exec kubectl
		// commands.
		ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
		defer cancel()
		if _, err := exec.CommandContext(ctx, "kubectl", "exec",
			args[1], "-n", args[3], "--", "which",
			args[5]).CombinedOutput(); err != nil || ctx.Err() == context.DeadlineExceeded {
			os.Remove(f.Name())
			return
		}
	}
	// Write prompt as header and the output as body, and / or error but delete empty output.
	output, err := execCommand(cmd, args...)
	if err != nil {
		fmt.Fprintf(f, fmt.Sprintf("> Error while running '%s':  %s\n\n", prompt, err))
	}
	// We deliberately continue in case there was a error but the output
	// produced might have useful information
	if strings.Contains(output, "```") {
		// Already contains Markdown, print as is.
		fmt.Fprint(f, output)
	} else if len(output) > 0 {
		fmt.Fprintf(f, fmt.Sprintf("# %s\n\n```\n%s\n```\n", prompt, output))
	} else {
		// Empty file
		os.Remove(f.Name())
	}
}

// split takes a commmand prompt and returns the command and arguments seperately
func split(prompt string) (string, []string) {
	// Split the command and arguments
	split := strings.Split(prompt, " ")
	argc := len(split)
	var args []string
	cmd := split[0]

	if argc > 1 {
		args = split[1:]
	}

	return cmd, args
}

func getCiliumPods(namespace, label string) ([]string, error) {
	output, err := execCommand("kubectl", "-n", namespace, "get", "pods", "-l", label)
	if err != nil {
		return nil, err
	}
	var ciliumPods []string

	lines := strings.Split(output, "\n")

	for _, l := range lines {
		if !strings.HasPrefix(l, "cilium") {
			continue
		}
		// NAME           READY     STATUS    RESTARTS   AGE
		// cilium-cfmww   0/1       Running   0          3m
		// ^
		pod := strings.Split(l, " ")[0]
		ciliumPods = append(ciliumPods, pod)
	}

	return ciliumPods, nil
}
