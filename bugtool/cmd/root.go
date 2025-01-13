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
	"github.com/cilium/cilium/pkg/cmdref"
	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/safeio"
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

// ExtraCommandsFunc represents a function that builds and returns a list of extra commands
// to gather additional information in specific environments.
//
// confDir is the directory where the output of "config commands" (e.g: "uname -r") is stored.
// cmdDir is the directory where the output of "info commands" (e.g: "cilium-dbg debuginfo",
// "cilium-dbg metrics list" and pprof traces) is stored.
//
// It returns a slice of strings with all the commands to be executed.
type ExtraCommandsFunc func(confDir string, cmdDir string) []string

// ExtraCommands is a slice of ExtraCommandsFunc each of which generates a list of additional
// commands to be executed alongside the default ones.
var ExtraCommands []ExtraCommandsFunc

var (
	archive            bool
	archiveType        string
	dumpPath           string
	host               string
	execTimeout        time.Duration
	configPath         string
	dryRunMode         bool
	enableMarkdown     bool
	archivePrefix      string
	getPProf           bool
	pprofDebug         int
	envoyDump          bool
	envoyMetrics       bool
	pprofPort          int
	traceSeconds       int
	parallelWorkers    int
	excludeObjectFiles bool
	hubbleMetrics      bool
	hubbleMetricsPort  int
)

func init() {
	BugtoolRootCmd.Flags().BoolVar(&archive, "archive", true, "Create archive when false skips deletion of the output directory")
	BugtoolRootCmd.Flags().BoolVar(&getPProf, "get-pprof", false, "When set, only gets the pprof traces from the cilium-agent binary")
	BugtoolRootCmd.Flags().IntVar(&pprofDebug, "pprof-debug", 0, "Debug pprof args")
	BugtoolRootCmd.Flags().BoolVar(&envoyDump, "envoy-dump", true, "When set, dump envoy configuration from unix socket")
	BugtoolRootCmd.Flags().BoolVar(&envoyMetrics, "envoy-metrics", true, "When set, dump envoy prometheus metrics from unix socket")
	BugtoolRootCmd.Flags().IntVar(&pprofPort,
		"pprof-port", option.PprofPortAgent,
		fmt.Sprintf(
			"Pprof port to connect to. Known Cilium component ports are agent:%d, operator:%d, apiserver:%d",
			option.PprofPortAgent, operatorOption.PprofPortOperator, apiserverOption.PprofPortClusterMesh,
		),
	)
	BugtoolRootCmd.Flags().IntVar(&traceSeconds, "pprof-trace-seconds", 180, "Amount of seconds used for pprof CPU traces")
	BugtoolRootCmd.Flags().StringVarP(&archiveType, "archiveType", "o", "tar", "Archive type: tar | gz")
	BugtoolRootCmd.Flags().BoolVar(&dryRunMode, "dry-run", false, "Create configuration file of all commands that would have been executed")
	BugtoolRootCmd.Flags().StringVarP(&dumpPath, "tmp", "t", defaultDumpPath, "Path to store extracted files. Use '-' to send to stdout.")
	BugtoolRootCmd.Flags().StringVarP(&host, "host", "H", "", "URI to server-side API")
	BugtoolRootCmd.Flags().DurationVarP(&execTimeout, "exec-timeout", "", 30*time.Second, "The default timeout for any cmd execution in seconds")
	BugtoolRootCmd.Flags().StringVarP(&configPath, "config", "", "./.cilium-bugtool.config", "Configuration to decide what should be run")
	BugtoolRootCmd.Flags().BoolVar(&enableMarkdown, "enable-markdown", false, "Dump output of commands in markdown format")
	BugtoolRootCmd.Flags().StringVarP(&archivePrefix, "archive-prefix", "", "", "String to prefix to name of archive if created (e.g., with cilium pod-name)")
	BugtoolRootCmd.Flags().IntVar(&parallelWorkers, "parallel-workers", 0, "Maximum number of parallel worker tasks, use 0 for number of CPUs")
	BugtoolRootCmd.Flags().BoolVar(&excludeObjectFiles, "exclude-object-files", false, "Exclude per-endpoint object files. Template object files will be kept")
	BugtoolRootCmd.Flags().BoolVar(&hubbleMetrics, "hubble-metrics", true, "When set, hubble prometheus metrics")
	BugtoolRootCmd.Flags().IntVar(&hubbleMetricsPort, "hubble-metrics-port", 9965, "Port to query for hubble metrics")
	BugtoolRootCmd.AddCommand(cmdref.NewCmd(BugtoolRootCmd))
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
	case "tar", "gz":
		return true
	}
	return false
}

type postProcessFunc func(output []byte) ([]byte, error)

var envoySecretMask = jsonFieldMaskPostProcess([]string{
	// Cilium LogEntry -> KafkaLogEntry{l7} -> KafkaLogEntry{api_key}
	"api_key",
	// This could be from one of the following:
	// - Cilium NetworkPolicy -> PortNetworkPolicy{ingress_per_port_policies, egress_per_port_policies}
	//	-> PortNetworkPolicyRule{rules} -> TLSContext{downstream_tls_context, upstream_tls_context}
	// - Upstream Envoy tls_certificate
	"trusted_ca",
	"certificate_chain",
	"private_key",
})

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

	if os.Getuid() != 0 {
		// When the user is not root, debuginfo and BPF related commands can fail.
		fmt.Fprintf(os.Stderr, "Warning, some of the BPF commands might fail when run as not root\n")
	}

	commands := defaultCommands(confDir, cmdDir)
	for _, f := range ExtraCommands {
		commands = append(commands, f(confDir, cmdDir)...)
	}

	if dryRunMode {
		dryRun(configPath, commands)
		fmt.Fprintf(os.Stderr, "Configuration file at %s\n", configPath)
		return
	}

	// Check if there is a non-empty user supplied configuration
	if config, _ := loadConfigFile(configPath); config != nil && len(config.Commands) > 0 {
		// All of of the commands run are from the configuration file
		commands = config.Commands
	}

	if getPProf {
		err := pprofTraces(cmdDir, pprofDebug)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create debug directory %s\n", err)
			os.Exit(1)
		}
	} else {
		if envoyDump {
			if err := dumpEnvoy(cmdDir, "http://admin/config_dump?include_eds", "envoy-config.json", envoySecretMask); err != nil {
				fmt.Fprintf(os.Stderr, "Unable to dump envoy config: %s\n", err)
			}
			if err := dumpEnvoy(cmdDir, "http://admin/listeners", "envoy-listeners.txt", nil); err != nil {
				fmt.Fprintf(os.Stderr, "Unable to dump envoy listeners: %s\n", err)
			}

			if err := dumpEnvoy(cmdDir, "http://admin/clusters", "envoy-clusters.txt", nil); err != nil {
				fmt.Fprintf(os.Stderr, "Unable to dump envoy clusters: %s\n", err)
			}

			if err := dumpEnvoy(cmdDir, "http://admin/server_info", "envoy-server-info.json", nil); err != nil {
				fmt.Fprintf(os.Stderr, "Unable to dump envoy server info: %s\n", err)
			}
		}

		if envoyMetrics {
			if err := dumpEnvoy(cmdDir, "http://admin/stats/prometheus", "envoy-metrics.txt", nil); err != nil {
				fmt.Fprintf(os.Stderr, "Unable to retrieve envoy prometheus metrics: %s\n", err)
			}
		}

		if hubbleMetrics {
			if err := dumpHubbleMetrics(cmdDir); err != nil {
				fmt.Fprintf(os.Stderr, "Unable to retrieve hubble prometheus metrics: %s\n", err)
			}
		}

		defer printDisclaimer()
		runAll(commands, cmdDir)

		if excludeObjectFiles {
			removeObjectFiles(cmdDir)
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
func dryRun(configPath string, commands []string) {
	if err := save(&BugtoolConfiguration{commands}, configPath); err != nil {
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

func runAll(commands []string, cmdDir string) {
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
			writeCmdToFile(cmdDir, cmd, enableMarkdown, nil)
			continue
		}

		err := wp.Submit(cmd, func(_ context.Context) error {
			if strings.Contains(cmd, "xfrm state") {
				//  Output of 'ip -s xfrm state' needs additional processing to replace
				// raw keys by their hash.
				writeCmdToFile(cmdDir, cmd, enableMarkdown, hashEncryptionKeys)
			} else {
				writeCmdToFile(cmdDir, cmd, enableMarkdown, nil)
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

func removeObjectFiles(cmdDir string) {
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

	path := filepath.Join(cmdDir, defaults.StateDir)
	rmFunc(path)
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
func writeCmdToFile(cmdDir, prompt string, enableMarkdown bool, postProcess func(output []byte) []byte) {
	// Clean up the filename
	name := strings.Replace(prompt, "/", " ", -1)
	name = strings.Replace(name, " ", "-", -1)
	suffix := ".md"
	if strings.HasSuffix(name, "html") {
		// If the command we run ends in 'html' (such as 'metrics/html'), write out the
		// output as a HTML file.
		suffix = ".html"
		enableMarkdown = false
	}
	f, err := os.Create(filepath.Join(cmdDir, name+suffix))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create file %s\n", err)
		return
	}
	defer f.Close()

	cmd := strings.Split(prompt, " ")[0]

	// The command does not exist, abort.
	if _, err := exec.LookPath(cmd); err != nil {
		os.Remove(f.Name())
		return
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
			fmt.Fprintf(f, "# %s\n\n```\n%s\n```\n", prompt, output)
		}
	}

	if err != nil {
		fmt.Fprintf(f, "> Error while running '%s':  %s\n\n", prompt, err)
	}
}

func dumpHubbleMetrics(rootDir string) error {
	httpClient := http.DefaultClient
	url := fmt.Sprintf("http://localhost:%d/metrics", hubbleMetricsPort)
	return downloadToFile(httpClient, url, filepath.Join(rootDir, "hubble-metrics.txt"))
}

func dumpEnvoy(rootDir string, resource string, fileName string, postProcess postProcessFunc) error {
	// curl --unix-socket /var/run/cilium/envoy/sockets/admin.sock http:/admin/config_dump\?include_eds > dump.json
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/cilium/envoy/sockets/admin.sock")
			},
		},
	}

	if postProcess == nil {
		return downloadToFile(c, resource, filepath.Join(rootDir, fileName))
	}
	return downloadToFileWithPostProcess(c, resource, filepath.Join(rootDir, fileName), postProcess)
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
	writeCmdToFile(rootDir, cmd, enableMarkdown, nil)

	cmd = fmt.Sprintf("gops stats $(pidof %s)", components.CiliumAgentName)
	writeCmdToFile(rootDir, cmd, enableMarkdown, nil)

	cmd = fmt.Sprintf("gops memstats $(pidof %s)", components.CiliumAgentName)
	writeCmdToFile(rootDir, cmd, enableMarkdown, nil)

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

// downloadToFileWithPostProcess downloads the content from the given URL and writes it to the given file.
// The content is then post-processed using the given postProcess function before being written to the file.
// Note: Please use downloadToFile instead of this function if no post-processing is required.
func downloadToFileWithPostProcess(client *http.Client, url, file string, postProcess postProcessFunc) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}
	b, err := safeio.ReadAllLimit(resp.Body, safeio.MB)
	if err != nil {
		return err
	}

	b, err = postProcess(b)
	if err != nil {
		return err
	}
	return os.WriteFile(file, b, 0644)
}
