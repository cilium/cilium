// Copyright 2016-2017 Authors of Cilium
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

package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/api/v1/server/restapi"
	health "github.com/cilium/cilium/cilium-health/launch"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/daemon/defaults"
	"github.com/cilium/cilium/daemon/options"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/version"
	"github.com/cilium/cilium/pkg/workloads"
	"github.com/cilium/cilium/pkg/workloads/containerd"

	"github.com/go-openapi/loads"
	gops "github.com/google/gops/agent"
	go_version "github.com/hashicorp/go-version"
	flags "github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/viper"
)

var (
	minKernelVer, _ = go_version.NewConstraint(">= 4.8.0")
	minClangVer, _  = go_version.NewConstraint(">= 3.8.0")

	recKernelVer, _ = go_version.NewConstraint(">= 4.9.0")
	recClangVer, _  = go_version.NewConstraint(">= 3.9.0")
)

const (
	argDebugVerbose = "debug-verbose"
	// list of supported verbose debug groups
	argDebugVerboseFlow    = "flow"
	argDebugVerboseKvstore = "kvstore"
	argDebugVerboseEnvoy   = "envoy"
)

var (
	config = NewConfig()

	log = logging.DefaultLogger

	// Arguments variables keep in alphabetical order

	// autoIPv6NodeRoutes automatically adds L3 direct routing when using direct mode (-d)
	autoIPv6NodeRoutes    bool
	bpfRoot               string
	cmdRefDir             string
	containerRuntimes     []string
	debugVerboseFlags     []string
	disableConntrack      bool
	dockerEndpoint        string
	enableLogstash        bool
	enableTracing         bool
	k8sAPIServer          string
	k8sKubeConfigPath     string
	kvStore               string
	labelPrefixFile       string
	loggers               []string
	logstashAddr          string
	logstashProbeTimer    uint32
	masquerade            bool
	nat46prefix           string
	prometheusServeAddr   string
	singleClusterRoute    bool
	socketPath            string
	tracePayloadLen       int
	v4Address             string
	v4ClusterCidrMaskSize int
	v4Prefix              string
	v4ServicePrefix       string
	v6Address             string
	v6Prefix              string
	v6ServicePrefix       string
	validLabels           []string
)

var (
	logOpts               = make(map[string]string)
	kvStoreOpts           = make(map[string]string)
	containerRuntimesOpts = make(map[string]string)
	cfgFile               string

	// RootCmd represents the base command when called without any subcommands
	RootCmd = &cobra.Command{
		Use:   "cilium-agent",
		Short: "Run the cilium agent",
		Run: func(cmd *cobra.Command, args []string) {
			initEnv(cmd)
			runDaemon()
		},
	}
)

func main() {

	// Open socket for using gops to get stacktraces of the agent.
	if err := gops.Listen(gops.Options{}); err != nil {
		errorString := fmt.Sprintf("unable to start gops: %s", err)
		fmt.Println(errorString)
		os.Exit(-1)
	}

	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func parseKernelVersion(ver string) (*go_version.Version, error) {
	verStrs := strings.Split(ver, ".")
	switch {
	case len(verStrs) < 2:
		return nil, fmt.Errorf("unable to get kernel version from %q", ver)
	case len(verStrs) < 3:
		verStrs = append(verStrs, "0")
	}
	// We are assuming the kernel version will be something as:
	// 4.9.17-040917-generic

	// If verStrs is []string{ "4", "9", "17-040917-generic" }
	// then we need to retrieve patch number.
	patch := regexp.MustCompilePOSIX(`^[0-9]+`).FindString(verStrs[2])
	if patch == "" {
		verStrs[2] = "0"
	} else {
		verStrs[2] = patch
	}
	return go_version.NewVersion(strings.Join(verStrs[:3], "."))
}

func getKernelVersion() (*go_version.Version, error) {
	verOut, err := exec.Command("uname", "-r").CombinedOutput()
	if err != nil {
		log.WithError(err).Fatal("kernel version: NOT OK")
	}
	return parseKernelVersion(string(verOut))
}

func getClangVersion(filePath string) (*go_version.Version, error) {
	verOut, err := exec.Command(filePath, "--version").CombinedOutput()
	if err != nil {
		log.WithError(err).Fatal("clang version: NOT OK")
	}
	res := regexp.MustCompile(`(clang version )([^ ]*)`).FindStringSubmatch(string(verOut))
	if len(res) != 3 {
		log.Fatalf("clang version: NOT OK: unable to get clang's version "+
			"from: %q", string(verOut))
	}
	// at this point res is []string{"clang", "version", "maj.min.patch"}
	verStrs := strings.Split(res[2], ".")
	if len(verStrs) < 3 {
		return nil, fmt.Errorf("unable to get clang version from %q", string(verOut))
	}
	v := strings.Join(verStrs[:3], ".")
	// Handle Ubuntu versioning by removing the dash and everything after.
	// F. ex. `4.0.0-1ubuntu1~16 -> 4.0.0` and `3.8.0-2ubuntu4 -> 3.8.0`.
	v = strings.Split(v, "-")[0]
	return go_version.NewVersion(v)
}

func checkBPFLogs(logType string, fatal bool) {
	bpfLogFile := logType + ".log"
	bpfLogPath := filepath.Join(config.StateDir, bpfLogFile)

	if _, err := os.Stat(bpfLogPath); os.IsNotExist(err) {
		log.Infof("%s check: OK!", logType)
	} else if err == nil {
		bpfFeaturesLog, err := ioutil.ReadFile(bpfLogPath)
		if err != nil {
			log.WithError(err).WithField(logfields.Path, bpfLogPath).Fatalf("%s check: NOT OK. Unable to read", logType)
		}
		printer := log.Debugf
		if fatal {
			printer = log.Errorf
			printer("%s check: NOT OK", logType)
		} else {
			printer("%s check: Some features may be limited:", logType)
		}
		lines := strings.Trim(string(bpfFeaturesLog), "\n")
		for _, line := range strings.Split(lines, "\n") {
			printer(line)
		}
		if fatal {
			log.Fatalf("%s check failed.", logType)
		}
	} else {
		log.WithError(err).WithField(logfields.Path, bpfLogPath).Fatalf("%s check: NOT OK. Unable to read", logType)
	}
}

func checkMinRequirements() {
	kernelVersion, err := getKernelVersion()
	if err != nil {
		log.WithError(err).Fatal("kernel version: NOT OK")
	}
	if !minKernelVer.Check(kernelVersion) {
		log.Fatalf("kernel version: NOT OK: minimal supported kernel "+
			"version is %s; kernel version that is running is: %s", minKernelVer, kernelVersion)
	}

	if filePath, err := exec.LookPath("clang"); err != nil {
		log.WithError(err).Fatal("clang: NOT OK")
	} else {
		clangVersion, err := getClangVersion(filePath)
		if err != nil {
			log.WithError(err).Fatal("clang: NOT OK")
		}
		if !minClangVer.Check(clangVersion) {
			log.Fatalf("clang version: NOT OK: minimal supported clang "+
				"version is %s; clang version that is running is: %s", minClangVer, clangVersion)
		}
		//clang >= 3.9 / kernel < 4.9 - does not work
		if recClangVer.Check(clangVersion) && !recKernelVer.Check(kernelVersion) {
			log.Fatalf("clang (%s) and kernel (%s) version: NOT OK: please upgrade "+
				"your kernel version to at least %s",
				clangVersion, kernelVersion, recKernelVer)
		}
		log.Infof("clang (%s) and kernel (%s) versions: OK!", clangVersion, kernelVersion)
	}

	if filePath, err := exec.LookPath("llc"); err != nil {
		log.WithError(err).Fatal("llc: NOT OK")
	} else {
		lccVersion, err := exec.Command(filePath, "--version").CombinedOutput()
		if err == nil {
			if strings.Contains(strings.ToLower(string(lccVersion)), "debug") {
				log.Warn("llc version was compiled in debug mode, expect higher latency!")
			}
		}
		// /usr/include/gnu/stubs-32.h is installed by 'glibc-devel.i686' in fedora
		// /usr/include/sys/cdefs.h is installed by 'libc6-dev-i386' in ubuntu
		// both files exist on both systems but cdefs.h already exists in fedora
		// without 'glibc-devel.i686' so we check for 'stubs-32.h first.
		if _, err := os.Stat("/usr/include/gnu/stubs-32.h"); os.IsNotExist(err) {
			log.Fatal("linking environment: NOT OK, please make sure you have 'glibc-devel.i686' if you use fedora system or 'libc6-dev-i386' if you use ubuntu system")
		}
		if _, err := os.Stat("/usr/include/sys/cdefs.h"); os.IsNotExist(err) {
			log.Fatal("linking environment: NOT OK, please make sure you have 'libc6-dev-i386' in your ubuntu system")
		}
		log.Info("linking environment: OK!")
	}

	globalsDir := filepath.Join(config.StateDir, "globals")
	if err := os.MkdirAll(globalsDir, defaults.StateDirRights); err != nil {
		log.WithError(err).WithField(logfields.Path, globalsDir).Fatal("Could not create runtime directory")
	}
	if err := os.Chdir(config.LibDir); err != nil {
		log.WithError(err).WithField(logfields.Path, config.LibDir).Fatal("Could not change to runtime directory")
	}
	probeScript := filepath.Join(config.BpfDir, "run_probes.sh")
	if err := exec.Command(probeScript, config.BpfDir, config.StateDir).Run(); err != nil {
		log.WithError(err).Fatal("BPF Verifier: NOT OK. Unable to run checker for bpf_features")
	}
	if _, err := os.Stat(filepath.Join(globalsDir, "bpf_features.h")); os.IsNotExist(err) {
		log.WithError(err).WithField(logfields.Path, globalsDir).Fatal("BPF Verifier: NOT OK. Unable to read bpf_features.h")
	}

	checkBPFLogs("bpf_requirements", true)
	checkBPFLogs("bpf_features", false)
}

func init() {
	cobra.OnInitialize(initConfig)
	flags := RootCmd.Flags()
	flags.String(
		"access-log", "", "Path to access log of supported L7 requests observed")
	flags.StringSlice(
		"agent-labels", []string{}, "Additional labels to identify this agent")
	flags.StringVar(&config.AllowLocalhost,
		"allow-localhost", AllowLocalhostAuto, "Policy when to allow local stack to reach local endpoints { auto | always | policy } ")
	flags.Bool(
		"auto-ipv6-node-routes", false, "Automatically adds IPv6 L3 routes to reach other nodes for non-overlay mode (--device) (BETA)")
	flags.StringVar(&bpfRoot,
		"bpf-root", "", "Path to BPF filesystem")
	flags.StringVar(&cfgFile,
		"config", "", `Configuration file (default "$HOME/ciliumd.yaml")`)
	flags.StringSliceVar(&containerRuntimes,
		"container-runtime", []string{"auto"}, `Sets the container runtime(s) used by Cilium { docker | none | auto }"`)
	flags.Var(option.NewNamedMapOptions("container-runtime-endpoints", &containerRuntimesOpts, nil),
		"container-runtime-endpoint", `Container runtime(s) endpoint(s). (default: --container-runtime-endpoint=docker=`+workloads.GetRuntimeDefaultOpt(workloads.Docker).Endpoint+`)`)
	flags.BoolP(
		"debug", "D", false, "Enable debugging mode")
	flags.StringSliceVar(&debugVerboseFlags, argDebugVerbose, []string{}, "List of enabled verbose debug groups")
	flags.StringVarP(&config.Device,
		"device", "d", "undefined", "Device facing cluster/external network for direct L3 (non-overlay mode)")
	flags.BoolVar(&disableConntrack,
		"disable-conntrack", false, "Disable connection tracking")
	flags.BoolVar(&config.IPv4Disabled,
		"disable-ipv4", false, "Disable IPv4 mode")
	flags.Bool("disable-k8s-services",
		false, "Disable east-west K8s load balancing by cilium")
	flags.StringVarP(&dockerEndpoint,
		"docker", "e", workloads.GetRuntimeDefaultOpt(workloads.Docker).Endpoint, "Path to docker runtime socket (DEPRECATED: use container-runtime-endpoint instead)")
	flags.String("enable-policy", endpoint.DefaultEnforcement, "Enable policy enforcement")
	flags.BoolVar(&enableTracing,
		"enable-tracing", false, "Enable tracing while determining policy (debugging)")
	flags.String("envoy-log", "", "Path to a separate Envoy log file, if any")
	flags.String("http-403-msg", "", "Message returned in proxy L7 403 body")
	flags.MarkHidden("http-403-msg")
	flags.Bool("disable-envoy-version-check", false, "Do not perform Envoy binary version check on startup")
	flags.MarkHidden("disable-envoy-version-check")
	// Disable version check if Envoy build is disabled
	viper.BindEnv("disable-envoy-version-check", "CILIUM_DISABLE_ENVOY_BUILD")
	flags.IntVar(&v4ClusterCidrMaskSize,
		"ipv4-cluster-cidr-mask-size", 8, "Mask size for the cluster wide CIDR")
	flags.StringVar(&v4Prefix,
		"ipv4-range", AutoCIDR, "Per-node IPv4 endpoint prefix, e.g. 10.16.0.0/16")
	flags.StringVar(&v6Prefix,
		"ipv6-range", AutoCIDR, "Per-node IPv6 endpoint prefix, must be /96, e.g. fd02:1:1::/96")
	flags.StringVar(&v4ServicePrefix,
		"ipv4-service-range", AutoCIDR, "Kubernetes IPv4 services CIDR if not inside cluster prefix")
	flags.StringVar(&v6ServicePrefix,
		"ipv6-service-range", AutoCIDR, "Kubernetes IPv6 services CIDR if not inside cluster prefix")
	flags.StringVar(&k8sAPIServer,
		"k8s-api-server", "", "Kubernetes api address server (for https use --k8s-kubeconfig-path instead)")
	flags.StringVar(&k8sKubeConfigPath,
		"k8s-kubeconfig-path", "", "Absolute path of the kubernetes kubeconfig file")
	flags.BoolVar(&config.KeepConfig,
		"keep-config", false, "When restoring state, keeps containers' configuration in place")
	flags.BoolVar(&config.KeepTemplates,
		"keep-bpf-templates", false, "Do not restore BPF template files from binary")
	flags.StringVar(&kvStore,
		"kvstore", "", "Key-value store type")
	flags.Var(option.NewNamedMapOptions("kvstore-opts", &kvStoreOpts, nil),
		"kvstore-opt", "Key-value store options")
	flags.StringVar(&labelPrefixFile,
		"label-prefix-file", "", "Valid label prefixes file path")
	flags.StringSliceVar(&validLabels,
		"labels", []string{}, "List of label prefixes used to determine identity of an endpoint")
	flags.StringVar(&config.LBInterface,
		"lb", "", "Enables load balancer mode where load balancer bpf program is attached to the given interface")
	flags.StringVar(&config.LibDir,
		"lib-dir", defaults.LibraryPath, "Directory path to store runtime build environment")
	flags.StringSliceVar(&loggers,
		"log-driver", []string{}, "Logging endpoints to use for example syslog, fluentd")
	flags.Var(option.NewNamedMapOptions("log-opts", &logOpts, nil),
		"log-opt", "Log driver options for cilium")
	flags.BoolVar(&enableLogstash,
		"logstash", false, "Enable logstash integration")
	flags.StringVar(&logstashAddr,
		"logstash-agent", "127.0.0.1:8080", "Logstash agent address")
	flags.Uint32Var(&logstashProbeTimer,
		"logstash-probe-timer", 10, "Logstash probe timer (seconds)")
	flags.StringVar(&nat46prefix,
		"nat46-range", node.DefaultNAT46Prefix, "IPv6 prefix to map IPv4 addresses to")
	flags.BoolVar(&masquerade,
		"masquerade", true, "Masquerade packets from endpoints leaving the host")
	flags.StringVar(&v6Address,
		"ipv6-node", "auto", "IPv6 address of node")
	flags.StringVar(&v4Address,
		"ipv4-node", "auto", "IPv4 address of node")
	flags.BoolVar(&config.RestoreState,
		"restore", true, "Restores state, if possible, from previous daemon")
	flags.Bool("sidecar-http-proxy", false, "Disable host HTTP proxy, assuming proxies in sidecar containers")
	flags.MarkHidden("sidecar-http-proxy")
	viper.BindEnv("sidecar-http-proxy", "CILIUM_SIDECAR_HTTP_PROXY")
	flags.BoolVar(&singleClusterRoute, "single-cluster-route", false,
		"Use a single cluster route instead of per node routes")
	flags.StringVar(&socketPath,
		"socket-path", defaults.SockPath, "Sets daemon's socket path to listen for connections")
	flags.StringVar(&config.RunDir,
		"state-dir", defaults.RuntimePath, "Directory path to store runtime state")
	flags.StringVarP(&config.Tunnel,
		"tunnel", "t", "vxlan", `Tunnel mode "vxlan" or "geneve"`)
	flags.IntVar(&tracePayloadLen,
		"trace-payloadlen", 128, "Length of payload to capture when tracing")
	flags.Bool(
		"version", false, "Print version information")
	flags.Bool(
		"pprof", false, "Enable serving the pprof debugging API")
	flags.StringVarP(&config.DevicePreFilter,
		"prefilter-device", "", "undefined", "Device facing external network for XDP prefiltering")
	flags.StringVarP(&config.ModePreFilter,
		"prefilter-mode", "", ModePreFilterNative, "Prefilter mode { "+ModePreFilterNative+" | "+ModePreFilterGeneric+" } (default: "+ModePreFilterNative+")")
	// We expect only one of the possible variables to be filled. The evaluation order is:
	// --prometheus-serve-addr, CILIUM_PROMETHEUS_SERVE_ADDR, then PROMETHEUS_SERVE_ADDR
	// The second environment variable (without the CILIUM_ prefix) is here to
	// handle the case where someone uses a new image with an older spec, and the
	// older spec used the older variable name.
	flags.StringVar(&prometheusServeAddr,
		"prometheus-serve-addr", "", "IP:Port on which to serve prometheus metrics (pass \":Port\" to bind on all interfaces, \"\" is off)")
	viper.BindEnv("prometheus-serve-addr", "CILIUM_PROMETHEUS_SERVE_ADDR")
	viper.BindEnv("prometheus-serve-addr-deprecated", "PROMETHEUS_SERVE_ADDR")

	flags.StringVar(&cmdRefDir,
		"cmdref", "", "Path to cmdref output directory")
	flags.MarkHidden("cmdref")

	viper.BindPFlags(flags)
}

// RestoreExecPermissions restores file permissions to 0740 of all files inside
// `searchDir` with the given regex `patterns`.
func RestoreExecPermissions(searchDir string, patterns ...string) error {
	fileList := []string{}
	err := filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
		for _, pattern := range patterns {
			if regexp.MustCompile(pattern).MatchString(f.Name()) {
				fileList = append(fileList, path)
				break
			}
		}
		return nil
	})
	for _, fileToChange := range fileList {
		// Changing files permissions to -rwx:r--:---, we are only
		// adding executable permission to the owner and keeping the
		// same permissions stored by go-bindata.
		if err := os.Chmod(fileToChange, os.FileMode(0740)); err != nil {
			return err
		}
	}
	return err
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if viper.GetBool("version") {
		fmt.Printf("Cilium %s\n", version.Version)
		os.Exit(0)
	}

	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	}

	viper.SetEnvPrefix("cilium")
	viper.SetConfigName("ciliumd") // name of config file (without extension)
	viper.AutomaticEnv()           // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func initEnv(cmd *cobra.Command) {

	// Logging should always be bootstrapped first. Do not add any code above this!
	logging.SetupLogging(loggers, logOpts, "cilium-agent", viper.GetBool("debug"))

	for _, grp := range debugVerboseFlags {
		switch grp {
		case argDebugVerboseFlow:
			log.Debugf("Enabling flow debug")
			flowdebug.Enable()
		case argDebugVerboseKvstore:
			kvstore.EnableTracing()
		case argDebugVerboseEnvoy:
			log.Debugf("Enabling Envoy tracing")
			envoy.EnableTracing()
		default:
			log.Warningf("Unknown verbose debug group: %s", grp)
		}
	}

	if cmdRefDir != "" {
		// Remove the line 'Auto generated by spf13/cobra on ...'
		cmd.DisableAutoGenTag = true
		if err := doc.GenMarkdownTreeCustom(cmd, cmdRefDir, filePrepend, linkHandler); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	common.RequireRootPrivilege("cilium-agent")

	log.Info("     _ _ _")
	log.Info(" ___|_| |_|_ _ _____")
	log.Info("|  _| | | | | |     |")
	log.Info("|___|_|_|_|___|_|_|_|")
	log.Infof("Cilium %s", version.Version)

	if viper.GetBool("disable-envoy-version-check") {
		log.Info("Envoy version check disabled")
	} else {
		envoyVersion := envoy.GetEnvoyVersion()
		log.Infof("%s", envoyVersion)

		envoyVersionArray := strings.Fields(envoyVersion)
		if len(envoyVersionArray) < 3 {
			log.Fatal("Truncated Envoy version string, cannot verify version match.")
		}
		// Make sure Envoy version matches ours
		if !strings.HasPrefix(envoyVersionArray[2], version.GetCiliumVersion().Revision) {
			log.Fatal("Envoy version mismatch, aborting.")
		}
	}

	if viper.GetBool("pprof") {
		pprof.Enable()
	}

	if config.IPv4Disabled {
		endpoint.IPv4Enabled = false
		node.EnableIPv4 = false
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.Path + ".RunDir": config.RunDir,
		logfields.Path + ".LibDir": config.LibDir,
	})

	config.BpfDir = filepath.Join(config.LibDir, defaults.BpfDir)
	scopedLog = scopedLog.WithField(logfields.Path+".BPFDir", defaults.BpfDir)
	if err := os.MkdirAll(config.RunDir, defaults.RuntimePathRights); err != nil {
		scopedLog.WithError(err).Fatal("Could not create runtime directory")
	}

	config.StateDir = filepath.Join(config.RunDir, defaults.StateDir)
	scopedLog = scopedLog.WithField(logfields.Path+".StateDir", config.StateDir)
	if err := os.MkdirAll(config.StateDir, defaults.StateDirRights); err != nil {
		scopedLog.WithError(err).Fatal("Could not create state directory")
	}

	if err := os.MkdirAll(config.LibDir, defaults.RuntimePathRights); err != nil {
		scopedLog.WithError(err).Fatal("Could not create library directory")
	}
	if !config.KeepTemplates {
		if err := RestoreAssets(config.LibDir, defaults.BpfDir); err != nil {
			scopedLog.WithError(err).Fatal("Unable to restore agent assets")
		}
		// Restore permissions of executable files
		if err := RestoreExecPermissions(config.LibDir, `.*\.sh`); err != nil {
			scopedLog.WithError(err).Fatal("Unable to restore agent assets")
		}
	}
	checkMinRequirements()

	if err := pidfile.Write(defaults.PidFilePath); err != nil {
		log.WithField(logfields.Path, defaults.PidFilePath).WithError(err).Fatal("Failed to create Pidfile")
	}

	config.AllowLocalhost = strings.ToLower(config.AllowLocalhost)
	switch config.AllowLocalhost {
	case AllowLocalhostAlways:
		config.alwaysAllowLocalhost = true
	case AllowLocalhostAuto, AllowLocalhostPolicy:
		config.alwaysAllowLocalhost = false
	default:
		log.Fatalf("Invalid setting for --allow-localhost, must be { %s, %s, %s }",
			AllowLocalhostAuto, AllowLocalhostAlways, AllowLocalhostPolicy)
	}

	config.ModePreFilter = strings.ToLower(config.ModePreFilter)
	switch config.ModePreFilter {
	case ModePreFilterNative:
		config.ModePreFilter = "xdpdrv"
	case ModePreFilterGeneric:
		config.ModePreFilter = "xdpgeneric"
	default:
		log.Fatalf("Invalid setting for --prefilter-mode, must be { %s, %s }",
			ModePreFilterNative, ModePreFilterGeneric)
	}

	scopedLog = log.WithField(logfields.Path, socketPath)
	socketDir := path.Dir(socketPath)
	if err := os.MkdirAll(socketDir, defaults.RuntimePathRights); err != nil {
		scopedLog.WithError(err).Fatal("Cannot mkdir directory for cilium socket")
	}

	if err := os.Remove(socketPath); !os.IsNotExist(err) && err != nil {
		scopedLog.WithError(err).Fatal("Cannot remove existing Cilium sock")
	}

	// The standard operation is to mount the BPF filesystem to the
	// standard location (/sys/fs/bpf). The user may chose to specify
	// the path to an already mounted filesystem instead. This is
	// useful if the daemon is being round inside a namespace and the
	// BPF filesystem is mapped into the slave namespace.
	bpf.CheckOrMountFS(bpfRoot)

	logging.DefaultLogLevel = defaults.DefaultLogLevel
	config.Opts.Set(endpoint.OptionDebug, viper.GetBool("debug"))

	autoIPv6NodeRoutes = viper.GetBool("auto-ipv6-node-routes")

	config.Opts.Set(endpoint.OptionDropNotify, true)
	config.Opts.Set(endpoint.OptionTraceNotify, true)
	config.Opts.Set(options.PolicyTracing, enableTracing)
	config.Opts.Set(endpoint.OptionConntrack, !disableConntrack)
	config.Opts.Set(endpoint.OptionConntrackAccounting, !disableConntrack)
	config.Opts.Set(endpoint.OptionConntrackLocal, false)

	policy.SetPolicyEnabled(strings.ToLower(viper.GetString("enable-policy")))

	if err := kvstore.Setup(kvStore, kvStoreOpts); err != nil {
		addrkey := fmt.Sprintf("%s.address", kvStore)
		addr := kvStoreOpts[addrkey]
		log.WithError(err).WithFields(logrus.Fields{
			"kvstore": kvStore,
			"address": addr,
		}).Fatal("Unable to setup kvstore")
	}

	if err := labels.ParseLabelPrefixCfg(validLabels, labelPrefixFile); err != nil {
		log.WithError(err).Fatal("Unable to parse Label prefix configuration")
	}

	_, r, err := net.ParseCIDR(nat46prefix)
	if err != nil {
		log.WithError(err).WithField(logfields.V6Prefix, nat46prefix).Fatal("Invalid NAT46 prefix")
	}

	config.NAT46Prefix = r

	// If device has been specified, use it to derive better default
	// allocation prefixes
	if config.Device != "undefined" {
		node.InitDefaultPrefix(config.Device)
	}

	if v6Address != "auto" {
		if ip := net.ParseIP(v6Address); ip == nil {
			log.WithField(logfields.IPAddr, v6Address).Fatal("Invalid IPv6 node address")
		} else {
			if !ip.IsGlobalUnicast() {
				log.WithField(logfields.IPAddr, ip).Fatal("Invalid IPv6 node address: not a global unicast address")
			}

			node.SetIPv6(ip)
		}
	}

	if v4Address != "auto" {
		if ip := net.ParseIP(v4Address); ip == nil {
			log.WithField(logfields.IPAddr, v4Address).Fatal("Invalid IPv4 node address")
		} else {
			node.SetExternalIPv4(ip)
		}
	}

	k8s.Configure(k8sAPIServer, k8sKubeConfigPath)

	// workaround for to use the values of the deprecated dockerEndpoint
	// variable if it is set with a different value than defaults.
	defaultDockerEndpoint := workloads.GetRuntimeDefaultOpt(workloads.Docker).Endpoint
	if defaultDockerEndpoint != dockerEndpoint {
		containerRuntimesOpts[string(workloads.Docker)] = dockerEndpoint
		log.Warn(`"docker" flag is deprecated.` +
			`Please use "--container-runtime-endpoint=docker=` + defaultDockerEndpoint + `" instead`)
	}

	err = workloads.ParseConfig(containerRuntimes, containerRuntimesOpts)
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize policy container runtimes")
		return
	}

	log.Infof("Container runtimes being used: %s", workloads.GetRuntimesString())
}
func runDaemon() {
	log.Info("Initializing daemon")
	d, err := NewDaemon(config)
	if err != nil {
		log.WithError(err).Fatal("Error while creating daemon")
		return
	}

	policy.InitReserved()

	log.Info("Starting connection tracking garbage collector")
	endpointmanager.EnableConntrackGC(!d.conf.IPv4Disabled, true)

	if enableLogstash {
		log.Info("Enabling Logstash")
		go EnableLogstash(logstashAddr, int(logstashProbeTimer))
	}

	log.Info("Launching node monitor daemon")
	go d.nodeMonitor.Run(path.Join(defaults.RuntimePath, defaults.EventsPipe), bpf.GetMapRoot())

	// Launch cilium-health in the same namespace as cilium.
	log.Info("Launching Cilium health daemon")
	d.ciliumHealth = &health.CiliumHealth{}
	go d.ciliumHealth.Run()

	// Launch another cilium-health as an endpoint, managed by cilium.
	log.Info("Launching Cilium health endpoint")
	addressing := d.getNodeAddressing()
	cancelHealth := health.LaunchAsEndpoint(d, addressing, d.conf.Opts)
	defer cancelHealth()

	if err := containerd.EnableEventListener(); err != nil {
		log.WithError(err).Fatal("Error while enabling containerd event watcher")
	}

	if err := d.EnableK8sWatcher(5 * time.Minute); err != nil {
		log.WithError(err).Fatal("Unable to establish connection to Kubernetes apiserver")
	}

	// This block is deprecated and will be removed later (GH-3050)
	logPath := filepath.Join(viper.GetString("state-dir"), "cilium-envoy.log")
	if err := os.Remove(logPath); !os.IsNotExist(err) && err != nil {
		log.WithError(err).Warn("Error deleting cilium-envoy.log")
	}

	swaggerSpec, err := loads.Analyzed(server.SwaggerJSON, "")
	if err != nil {
		log.WithError(err).Fatal("Cannot load swagger spec")
	}

	promAddr := viper.GetString("prometheus-serve-addr")
	if promAddr == "" {
		promAddr = viper.GetString("prometheus-serve-addr-deprecated")
	}
	if promAddr != "" {
		log.Infof("Serving prometheus metrics on %s", promAddr)
		if err := metrics.Enable(promAddr); err != nil {
			log.WithError(err).Fatal("Error while starting metrics")
		}
	}

	log.Info("Initializing Cilium API")
	api := restapi.NewCiliumAPI(swaggerSpec)

	api.Logger = log.Infof

	// /healthz/
	api.DaemonGetHealthzHandler = NewGetHealthzHandler(d)

	// /config/
	api.DaemonGetConfigHandler = NewGetConfigHandler(d)
	api.DaemonPatchConfigHandler = NewPatchConfigHandler(d)

	// /endpoint/
	api.EndpointGetEndpointHandler = NewGetEndpointHandler(d)

	// /endpoint/{id}
	api.EndpointGetEndpointIDHandler = NewGetEndpointIDHandler(d)
	api.EndpointPutEndpointIDHandler = NewPutEndpointIDHandler(d)
	api.EndpointPatchEndpointIDHandler = NewPatchEndpointIDHandler(d)
	api.EndpointDeleteEndpointIDHandler = NewDeleteEndpointIDHandler(d)

	// /endpoint/{id}config/
	api.EndpointGetEndpointIDConfigHandler = NewGetEndpointIDConfigHandler(d)
	api.EndpointPatchEndpointIDConfigHandler = NewPatchEndpointIDConfigHandler(d)

	// /endpoint/{id}/labels/
	api.EndpointGetEndpointIDLabelsHandler = NewGetEndpointIDLabelsHandler(d)
	api.EndpointPatchEndpointIDLabelsHandler = NewPatchEndpointIDLabelsHandler(d)

	// /endpoint/{id}/log/
	api.EndpointGetEndpointIDLogHandler = NewGetEndpointIDLogHandler(d)

	// /endpoint/{id}/healthz
	api.EndpointGetEndpointIDHealthzHandler = NewGetEndpointIDHealthzHandler(d)

	// /identity/
	api.PolicyGetIdentityHandler = newGetIdentityHandler(d)
	api.PolicyGetIdentityIDHandler = newGetIdentityIDHandler(d)

	// /policy/
	api.PolicyGetPolicyHandler = newGetPolicyHandler(d)
	api.PolicyPutPolicyHandler = newPutPolicyHandler(d)
	api.PolicyDeletePolicyHandler = newDeletePolicyHandler(d)

	// /policy/resolve/
	api.PolicyGetPolicyResolveHandler = NewGetPolicyResolveHandler(d)

	// /service/{id}/
	api.ServiceGetServiceIDHandler = NewGetServiceIDHandler(d)
	api.ServiceDeleteServiceIDHandler = NewDeleteServiceIDHandler(d)
	api.ServicePutServiceIDHandler = NewPutServiceIDHandler(d)

	// /service/
	api.ServiceGetServiceHandler = NewGetServiceHandler(d)

	// /prefilter/
	api.PrefilterGetPrefilterHandler = NewGetPrefilterHandler(d)
	api.PrefilterPatchPrefilterHandler = NewPatchPrefilterHandler(d)

	// /ipam/{ip}/
	api.IPAMPostIPAMHandler = NewPostIPAMHandler(d)
	api.IPAMPostIPAMIPHandler = NewPostIPAMIPHandler(d)
	api.IPAMDeleteIPAMIPHandler = NewDeleteIPAMIPHandler(d)

	// /debuginfo
	api.DaemonGetDebuginfoHandler = NewGetDebugInfoHandler(d)

	server := server.NewServer(api)
	server.EnabledListeners = []string{"unix"}
	server.SocketPath = flags.Filename(socketPath)
	defer server.Shutdown()

	server.ConfigureAPI()

	d.SendNotification(monitor.AgentNotifyStart, time.Now().String())

	log.Info("Daemon initialization completed")

	if err := server.Serve(); err != nil {
		log.WithError(err).Fatal("Error returned from non-returning Serve() call")
	}
}

func linkHandler(s string) string {
	// The generated files have a 'See also' section but the URL's are
	// hardcoded to use Markdown but we only want / have them in HTML
	// later.
	return strings.Replace(s, ".md", ".html", 1)
}

func filePrepend(s string) string {
	// Prepend a HTML comment that this file is autogenerated. So that
	// users are warned before fixing issues in the Markdown files.  Should
	// never show up on the web.
	return fmt.Sprintf("%s\n\n", "<!-- This file was autogenerated via cilium-agent --cmdref, do not edit manually-->")
}
