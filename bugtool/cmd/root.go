// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cilium/workerpool"
	"github.com/spf13/cobra"

	apiserverOption "github.com/cilium/cilium/clustermesh-apiserver/option"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
)

// BugtoolRootCmd is the top level command for the bugtool.
var BugtoolRootCmd = &cobra.Command{
	Use:   "cilium-bugtool [OPTIONS]",
	Short: "Collects agent & system information useful for bug reporting",
	Example: `	# Collect information and create archive file
	$ cilium-bugtool
	[...]

	# Collect and retrieve archive if Cilium is running in a Kubernetes pod
	$ kubectl get pods --namespace kube-system
	NAME                          READY     STATUS    RESTARTS   AGE
	cilium-kg8lv                  1/1       Running   0          13m
	[...]
	$ kubectl -n kube-system exec cilium-kg8lv -- cilium-bugtool
	$ kubectl cp kube-system/cilium-kg8lv:/tmp/cilium-bugtool-243785589.tar /tmp/cilium-bugtool-243785589.tar`,
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
	defaultDumpPath = "/tmp"
)

var (
	archive                  bool
	archiveType              string
	k8s                      bool
	dumpPath                 string
	host                     string
	k8sNamespace             string
	k8sLabel                 string
	execTimeout              time.Duration
	configPath               string
	dryRunMode               bool
	enableMarkdown           bool
	archivePrefix            string
	getPProf                 bool
	pprofDebug               int
	envoyDump                bool
	envoyMetrics             bool
	pprofPort                int
	traceSeconds             int
	parallelWorkers          int
	ciliumAgentContainerName string
	excludeObjectFiles       bool
)

func init() {
	BugtoolRootCmd.Flags().BoolVar(&archive, "archive", true, "Create archive when false skips deletion of the output directory")
	BugtoolRootCmd.Flags().BoolVar(&getPProf, "get-pprof", false, "When set, only gets the pprof traces from the cilium-agent binary")
	BugtoolRootCmd.Flags().IntVar(&pprofDebug, "pprof-debug", 1, "Debug pprof args")
	BugtoolRootCmd.Flags().BoolVar(&envoyDump, "envoy-dump", true, "When set, dump envoy configuration from unix socket")
	BugtoolRootCmd.Flags().BoolVar(&envoyMetrics, "envoy-metrics", true, "When set, dump envoy prometheus metrics from unix socket")
	BugtoolRootCmd.Flags().IntVar(&pprofPort,
		"pprof-port", option.PprofPortAgent,
		fmt.Sprintf(
			"Pprof port to connect to. Known Cilium component ports are agent:%d, operator:%d, apiserver:%d",
			option.PprofPortAgent, operatorOption.PprofPortOperator, apiserverOption.PprofPortAPIServer,
		),
	)
	BugtoolRootCmd.Flags().IntVar(&traceSeconds, "pprof-trace-seconds", 180, "Amount of seconds used for pprof CPU traces")
	BugtoolRootCmd.Flags().StringVarP(&archiveType, "archiveType", "o", "tar", "Archive type: tar | gz")
	BugtoolRootCmd.Flags().BoolVar(&k8s, "k8s-mode", false, "Require Kubernetes pods to be found or fail")
	BugtoolRootCmd.Flags().BoolVar(&dryRunMode, "dry-run", false, "Create configuration file of all commands that would have been executed")
	BugtoolRootCmd.Flags().StringVarP(&dumpPath, "tmp", "t", defaultDumpPath, "Path to store extracted files. Use '-' to send to stdout.")
	BugtoolRootCmd.Flags().StringVarP(&host, "host", "H", "", "URI to server-side API")
	BugtoolRootCmd.Flags().StringVarP(&k8sNamespace, "k8s-namespace", "", "kube-system", "Kubernetes namespace for Cilium pod")
	BugtoolRootCmd.Flags().StringVarP(&k8sLabel, "k8s-label", "", "k8s-app=cilium", "Kubernetes label for Cilium pod")
	BugtoolRootCmd.Flags().DurationVarP(&execTimeout, "exec-timeout", "", 30*time.Second, "The default timeout for any cmd execution in seconds")
	BugtoolRootCmd.Flags().StringVarP(&configPath, "config", "", "./.cilium-bugtool.config", "Configuration to decide what should be run")
	BugtoolRootCmd.Flags().BoolVar(&enableMarkdown, "enable-markdown", false, "Dump output of commands in markdown format")
	BugtoolRootCmd.Flags().StringVarP(&archivePrefix, "archive-prefix", "", "", "String to prefix to name of archive if created (e.g., with cilium pod-name)")
	BugtoolRootCmd.Flags().IntVar(&parallelWorkers, "parallel-workers", 0, "Maximum number of parallel worker tasks, use 0 for number of CPUs")
	BugtoolRootCmd.Flags().StringVarP(&ciliumAgentContainerName, "cilium-agent-container-name", "", "cilium-agent", "Name of the Cilium Agent main container (when k8s-mode is true)")
	BugtoolRootCmd.Flags().BoolVar(&excludeObjectFiles, "exclude-object-files", false, "Exclude per-endpoint object files. Template object files will be kept")
}

func getVerifyCiliumPods() (k8sPods []string) {
	if k8s {
		var err error
		// By default try to pick either Kubernetes or non-k8s (host mode). If
		// we find Cilium pod(s) then it's k8s-mode otherwise host mode.
		// Passing extra flags can override the default.
		k8sPods, err = getCiliumPods(k8sNamespace, k8sLabel)
		// When the k8s flag is set, perform extra checks that we actually do have pods or fail.
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\nFailed to find pods, is kube-apiserver running?\n", err)
			os.Exit(1)
		}
		if len(k8sPods) < 1 {
			fmt.Fprint(os.Stderr, "Found no pods, is kube-apiserver running?\n")
			os.Exit(1)
		}
	}
	if os.Getuid() != 0 && !k8s && len(k8sPods) == 0 {
		// When the k8s flag is not set and the user is not root,
		// debuginfo and BPF related commands can fail.
		fmt.Fprintf(os.Stderr, "Warning, some of the BPF commands might fail when run as not root\n")
	}

	return k8sPods
}

func removeIfEmpty(dir string) {
	files, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read directory %s\n", err)
		return
	} else if len(files) == 0 {
		if err := os.Remove(dir); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to delete directory %s\n", err)
			return
		}
	}

	fmt.Fprintf(os.Stderr, "Deleted empty directory %s\n", dir)
}

func isValidArchiveType(archiveType string) bool {
	switch archiveType {
	case
		"tar",
		"gz":
		return true
	}
	return false
}

func runTool() {
	// Validate archive type
	if !isValidArchiveType(archiveType) {
		fmt.Fprintf(os.Stderr, "Error: unsupported output type: %s, must be one of tar|gz\n", archiveType)
		os.Exit(1)
	}

	// Prevent collision with other directories
	nowStr := time.Now().Format("20060102-150405.999-0700-MST")
	var prefix string
	if archivePrefix != "" {
		prefix = fmt.Sprintf("%s-cilium-bugtool-%s-", archivePrefix, nowStr)
	} else {
		prefix = fmt.Sprintf("cilium-bugtool-%s-", nowStr)
	}
	sendArchiveToStdout := false
	if dumpPath == "-" {
		sendArchiveToStdout = true
		dumpPath = defaultDumpPath
	}
	dbgDir, err := os.MkdirTemp(dumpPath, prefix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create debug directory %s\n", err)
		os.Exit(1)
	}
	defer cleanup(dbgDir)
	cmdDir := createDir(dbgDir, "cmd")
	confDir := createDir(dbgDir, "conf")

	k8sPods := getVerifyCiliumPods()

	var commands []string
	if dryRunMode {
		dryRun(configPath, k8sPods, confDir, cmdDir)
		fmt.Fprintf(os.Stderr, "Configuration file at %s\n", configPath)
		return
	}

	if getPProf {
		err := pprofTraces(cmdDir, pprofDebug)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create debug directory %s\n", err)
			os.Exit(1)
		}
	} else {
		if envoyDump {
			if err := dumpEnvoy(cmdDir, "http://admin/config_dump?include_eds", "envoy-config.json"); err != nil {
				fmt.Fprintf(os.Stderr, "Unable to dump envoy config: %s\n", err)
			}
		}

		if envoyMetrics {
			if err := dumpEnvoy(cmdDir, "http://admin/stats/prometheus", "envoy-metrics.txt"); err != nil {
				fmt.Fprintf(os.Stderr, "Unable to retrieve envoy prometheus metrics: %s\n", err)
			}
		}

		// Check if there is a user supplied configuration
		if config, _ := loadConfigFile(configPath); config != nil {
			// All of of the commands run are from the configuration file
			commands = config.Commands
		}
		if len(commands) == 0 {
			// Found no configuration file or empty so fall back to default commands.
			commands = defaultCommands(confDir, cmdDir, k8sPods)
		}
		defer printDisclaimer()

		runAll(commands, cmdDir, k8sPods)

		if excludeObjectFiles {
			removeObjectFiles(cmdDir, k8sPods)
		}
	}

	removeIfEmpty(cmdDir)
	removeIfEmpty(confDir)

	if archive {
		switch archiveType {
		case "gz":
			gzipPath, err := createGzip(dbgDir, sendArchiveToStdout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to create gzip %s\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "\nGZIP at %s\n", gzipPath)
		case "tar":
			archivePath, err := createArchive(dbgDir, sendArchiveToStdout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to create archive %s\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "\nARCHIVE at %s\n", archivePath)
		}
	} else {
		fmt.Fprintf(os.Stderr, "\nDIRECTORY at %s\n", dbgDir)
	}
}

// dryRun creates the configuration file to show the user what would have been run.
// The same file can be used to modify what will be run by the bugtool.
func dryRun(configPath string, k8sPods []string, confDir, cmdDir string) {
	_, err := setupDefaultConfig(configPath, k8sPods, confDir, cmdDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", err)
		os.Exit(1)
	}
}

func printDisclaimer() {
	fmt.Fprint(os.Stderr, disclaimer)
}

func cleanup(dbgDir string) {
	if archive {
		var files []string

		switch archiveType {
		case "gz":
			files = append(files, dbgDir)
			files = append(files, fmt.Sprintf("%s.tar", dbgDir))
		case "tar":
			files = append(files, dbgDir)
		}

		for _, file := range files {
			if err := os.RemoveAll(file); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to cleanup temporary files %s\n", err)
			}
		}
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

func podPrefix(pod, cmd string) string {
	return fmt.Sprintf("kubectl exec %s -c %s -n %s -- %s", pod, ciliumAgentContainerName, k8sNamespace, cmd)
}

func runAll(commands []string, cmdDir string, k8sPods []string) {
	if len(commands) == 0 {
		return
	}

	if parallelWorkers <= 0 {
		parallelWorkers = runtime.NumCPU()
	}

	wp := workerpool.New(parallelWorkers)
	for _, cmd := range commands {
		if strings.Contains(cmd, "tables") {
			// iptables commands hold locks so we can't have multiple runs. They
			// have to be run one at a time to avoid 'Another app is currently
			// holding the xtables lock...'
			writeCmdToFile(cmdDir, cmd, k8sPods, enableMarkdown, nil)
			continue
		}

		cmd := cmd // https://golang.org/doc/faq#closures_and_goroutines
		err := wp.Submit(cmd, func(_ context.Context) error {
			if strings.Contains(cmd, "xfrm state") {
				//  Output of 'ip -s xfrm state' needs additional processing to replace
				// raw keys by their hash.
				writeCmdToFile(cmdDir, cmd, k8sPods, enableMarkdown, hashEncryptionKeys)
			} else {
				writeCmdToFile(cmdDir, cmd, k8sPods, enableMarkdown, nil)
			}
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to submit task for command %q: %v\n", cmd, err)
			return
		}
	}

	// wait for all submitted tasks to complete
	_, err := wp.Drain()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error waiting for commands to complete: %v\n", err)
	}

	err = wp.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to close worker pool: %v\n", err)
	}
}

func removeObjectFiles(cmdDir string, k8sPods []string) {
	// Remove object files for each endpoint. Endpoints directories are in the
	// state directory and have numerical names.
	rmFunc := func(path string) {
		matches, err := filepath.Glob(filepath.Join(path, "[0-9]*", "*.o"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to exclude object files: %s\n", err)
		}
		for _, m := range matches {
			err = os.Remove(m)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to remove object file: %s\n", err)
			}
		}
	}

	if k8s {
		for _, pod := range k8sPods {
			path := filepath.Join(cmdDir, fmt.Sprintf("%s-%s", pod, defaults.StateDir))
			rmFunc(path)
		}
	} else {
		path := filepath.Join(cmdDir, defaults.StateDir)
		rmFunc(path)
	}
}

func execCommand(prompt string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, "bash", "-c", prompt).CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("exec timeout")
	}
	return output, err
}

// writeCmdToFile will execute command and write markdown output to a file
func writeCmdToFile(cmdDir, prompt string, k8sPods []string, enableMarkdown bool, postProcess func(output []byte) []byte) {
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
			args[5]).CombinedOutput(); err != nil || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			os.Remove(f.Name())
			return
		}
	}

	var output []byte

	// If we don't need to postprocess the command output, write the output to a file directly
	// without buffering.
	if !enableMarkdown && postProcess == nil {
		cmd := exec.Command("bash", "-c", prompt)
		cmd.Stdout = f
		cmd.Stderr = f
		err = cmd.Run()
	} else {
		output, err = execCommand(prompt)
		// Post-process the output if necessary
		if postProcess != nil {
			output = postProcess(output)
		}

		// We deliberately continue in case there was a error but the output
		// produced might have useful information
		if bytes.Contains(output, []byte("```")) || !enableMarkdown {
			// Already contains Markdown, print as is.
			fmt.Fprint(f, string(output))
		} else if enableMarkdown && len(output) > 0 {
			// Write prompt as header and the output as body, and/or error but delete empty output.
			fmt.Fprint(f, fmt.Sprintf("# %s\n\n```\n%s\n```\n", prompt, output))
		}
	}

	if err != nil {
		fmt.Fprintf(f, "> Error while running '%s':  %s\n\n", prompt, err)
	}
}

// split takes a command prompt and returns the command and arguments separately
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
	output, err := execCommand(fmt.Sprintf("kubectl -n %s get pods -l %s", namespace, label))
	if err != nil {
		return nil, err
	}

	lines := bytes.Split(output, []byte("\n"))
	ciliumPods := make([]string, 0, len(lines))
	for _, l := range lines {
		if !bytes.HasPrefix(l, []byte("cilium")) {
			continue
		}
		// NAME           READY     STATUS    RESTARTS   AGE
		// cilium-cfmww   0/1       Running   0          3m
		// ^
		pod := bytes.Split(l, []byte(" "))[0]
		ciliumPods = append(ciliumPods, string(pod))
	}

	return ciliumPods, nil
}

func dumpEnvoy(rootDir string, resource string, fileName string) error {
	// curl --unix-socket /var/run/cilium/envoy/sockets/admin.sock http:/admin/config_dump\?include_eds > dump.json
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/cilium/envoy/sockets/admin.sock")
			},
		},
	}
	return downloadToFile(c, resource, filepath.Join(rootDir, fileName))
}

func pprofTraces(rootDir string, pprofDebug int) error {
	var wg sync.WaitGroup
	var profileErr error
	pprofHost := fmt.Sprintf("localhost:%d", pprofPort)
	wg.Add(1)
	httpClient := http.DefaultClient
	go func() {
		url := fmt.Sprintf("http://%s/debug/pprof/profile?seconds=%d", pprofHost, traceSeconds)
		dir := filepath.Join(rootDir, "pprof-cpu")
		profileErr = downloadToFile(httpClient, url, dir)
		wg.Done()
	}()

	url := fmt.Sprintf("http://%s/debug/pprof/trace?seconds=%d", pprofHost, traceSeconds)
	dir := filepath.Join(rootDir, "pprof-trace")
	err := downloadToFile(httpClient, url, dir)
	if err != nil {
		return err
	}

	url = fmt.Sprintf("http://%s/debug/pprof/heap?debug=%d", pprofHost, pprofDebug)
	dir = filepath.Join(rootDir, "pprof-heap")
	err = downloadToFile(httpClient, url, dir)
	if err != nil {
		return err
	}

	cmd := fmt.Sprintf("gops stack $(pidof %s)", components.CiliumAgentName)
	writeCmdToFile(rootDir, cmd, nil, enableMarkdown, nil)

	cmd = fmt.Sprintf("gops stats $(pidof %s)", components.CiliumAgentName)
	writeCmdToFile(rootDir, cmd, nil, enableMarkdown, nil)

	cmd = fmt.Sprintf("gops memstats $(pidof %s)", components.CiliumAgentName)
	writeCmdToFile(rootDir, cmd, nil, enableMarkdown, nil)

	wg.Wait()
	if profileErr != nil {
		return profileErr
	}
	return nil
}

func downloadToFile(client *http.Client, url, file string) error {
	out, err := os.Create(file)
	if err != nil {
		return err
	}
	defer out.Close()

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}
	_, err = io.Copy(out, resp.Body)
	return err
}
