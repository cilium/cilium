// Copyright 2016-2019 Authors of Cilium
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
	"context"
	"errors"
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
	"github.com/cilium/cilium/common"
	_ "github.com/cilium/cilium/pkg/alignchecker"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cleanup"
	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/controller"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/datapath/maps"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/endpointsynchronizer"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadinfo"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/sockops"
	"github.com/cilium/cilium/pkg/version"
	"github.com/cilium/cilium/pkg/versioncheck"
	"github.com/cilium/cilium/pkg/workloads"

	"github.com/go-openapi/loads"
	gops "github.com/google/gops/agent"
	go_version "github.com/hashicorp/go-version"
	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	minKernelVer = versioncheck.MustCompile(">= 4.8.0")
	minClangVer  = versioncheck.MustCompile(">= 3.8.0")

	recKernelVer = versioncheck.MustCompile(">= 4.9.0")
	recClangVer  = versioncheck.MustCompile(">= 3.9.0")
)

const (
	// list of supported verbose debug groups
	argDebugVerboseFlow    = "flow"
	argDebugVerboseKvstore = "kvstore"
	argDebugVerboseEnvoy   = "envoy"

	apiTimeout   = 60 * time.Second
	daemonSubsys = "daemon"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, daemonSubsys)

	bootstrapTimestamp = time.Now()

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

func init() {
	logging.DefaultLogger.Hooks.Add(metrics.NewLoggingHook(components.CiliumAgentName))
}

func daemonMain() {

	// Open socket for using gops to get stacktraces of the agent.
	if err := gops.Listen(gops.Options{}); err != nil {
		errorString := fmt.Sprintf("unable to start gops: %s", err)
		fmt.Println(errorString)
		os.Exit(-1)
	}
	interruptCh := registerSigHandler()
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	<-interruptCh
	os.Exit(0)
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
	var unameBuf unix.Utsname
	if err := unix.Uname(&unameBuf); err != nil {
		log.WithError(err).Fatal("kernel version: NOT OK")
	}
	return parseKernelVersion(string(unameBuf.Release[:]))
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
	bpfLogPath := filepath.Join(option.Config.StateDir, bpfLogFile)

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

	if option.Config.EnableIPv6 {
		if _, err := os.Stat("/proc/net/if_inet6"); os.IsNotExist(err) {
			log.Fatalf("kernel: ipv6 is enabled in agent but ipv6 is either disabled or not compiled in the kernel")
		}
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

	globalsDir := option.Config.GetGlobalsDir()
	if err := os.MkdirAll(globalsDir, defaults.StateDirRights); err != nil {
		log.WithError(err).WithField(logfields.Path, globalsDir).Fatal("Could not create runtime directory")
	}
	if err := os.Chdir(option.Config.LibDir); err != nil {
		log.WithError(err).WithField(logfields.Path, option.Config.LibDir).Fatal("Could not change to runtime directory")
	}
	probeScript := filepath.Join(option.Config.BpfDir, "run_probes.sh")
	if err := exec.Command(probeScript, option.Config.BpfDir, option.Config.StateDir).Run(); err != nil {
		log.WithError(err).Fatal("BPF Verifier: NOT OK. Unable to run checker for bpf_features")
	}
	featuresFilePath := filepath.Join(globalsDir, "bpf_features.h")
	if _, err := os.Stat(featuresFilePath); os.IsNotExist(err) {
		log.WithError(err).WithField(logfields.Path, globalsDir).Fatal("BPF Verifier: NOT OK. Unable to read bpf_features.h")
	}

	checkBPFLogs("bpf_requirements", true)
	checkBPFLogs("bpf_features", false)
	bpf.ReadFeatureProbes(featuresFilePath)
}

func init() {
	cobra.OnInitialize(initConfig)

	// Reset the help function to also exit, as we block elsewhere in interrupts
	// and would not exit when called with -h.
	oldHelpFunc := RootCmd.HelpFunc()
	RootCmd.SetHelpFunc(func(c *cobra.Command, a []string) {
		oldHelpFunc(c, a)
		os.Exit(0)
	})

	flags := RootCmd.Flags()

	// Validators
	option.Config.FixedIdentityMappingValidator = option.Validator(func(val string) (string, error) {
		vals := strings.Split(val, "=")
		if len(vals) != 2 {
			return "", fmt.Errorf(`invalid fixed identity: expecting "<numeric-identity>=<identity-name>" got %q`, val)
		}
		ni, err := identity.ParseNumericIdentity(vals[0])
		if err != nil {
			return "", fmt.Errorf(`invalid numeric identity %q: %s`, val, err)
		}
		if !identity.IsUserReservedIdentity(ni) {
			return "", fmt.Errorf(`invalid numeric identity %q: valid numeric identity is between %d and %d`,
				val, identity.UserReservedNumericIdentity.Uint32(), identity.MinimalNumericIdentity.Uint32())
		}
		lblStr := vals[1]
		lbl := labels.ParseLabel(lblStr)
		if lbl.IsReservedSource() {
			return "", fmt.Errorf(`invalid source %q for label: %s`, labels.LabelSourceReserved, lblStr)
		}
		return val, nil
	})

	// Env bindings
	flags.String(option.AccessLog, "", "Path to access log of supported L7 requests observed")
	option.BindEnv(option.AccessLog)

	flags.StringSlice(option.AgentLabels, []string{}, "Additional labels to identify this agent")
	option.BindEnv(option.AgentLabels)

	flags.String(option.AllowLocalhost, option.AllowLocalhostAuto, "Policy when to allow local stack to reach local endpoints { auto | always | policy }")
	option.BindEnv(option.AllowLocalhost)

	flags.Bool(option.LegacyAutoIPv6NodeRoutesName, false, "Deprecatd, use --auto-direct-node-routes")
	option.BindEnv(option.LegacyAutoIPv6NodeRoutesName)
	flags.MarkDeprecated(option.LegacyAutoIPv6NodeRoutesName, fmt.Sprintf("please use %s", option.EnableAutoDirectRoutingName))

	flags.String(option.BPFRoot, "", "Path to BPF filesystem")
	option.BindEnv(option.BPFRoot)

	flags.String(option.CGroupRoot, "", "Path to Cgroup2 filesystem")
	option.BindEnv(option.CGroupRoot)

	flags.Bool(option.BPFCompileDebugName, false, "Enable debugging of the BPF compilation process")
	option.BindEnv(option.BPFCompileDebugName)

	flags.Bool(option.SockopsEnableName, defaults.SockopsEnable, "Enable sockops when kernel supported")
	option.BindEnv(option.SockopsEnableName)

	flags.Int(option.ClusterIDName, 0, "Unique identifier of the cluster")
	option.BindEnv(option.ClusterIDName)

	flags.String(option.ClusterName, defaults.ClusterName, "Name of the cluster")
	option.BindEnv(option.ClusterName)

	flags.String(option.ClusterMeshConfigName, "", "Path to the ClusterMesh configuration directory")
	option.BindEnv(option.ClusterMeshConfigName)

	flags.String(option.ConfigFile, "", `Configuration file (default "$HOME/ciliumd.yaml")`)
	option.BindEnv(option.ConfigFile)

	flags.String(option.ConfigDir, "", `Configuration directory that contains a file for each option`)
	option.BindEnv(option.ConfigDir)

	flags.Uint(option.ConntrackGarbageCollectorInterval, 60, "Garbage collection interval for the connection tracking table (in seconds)")
	option.BindEnv(option.ConntrackGarbageCollectorInterval)

	flags.StringSlice(option.ContainerRuntime, []string{"auto"}, `Sets the container runtime(s) used by Cilium { containerd | crio | docker | none | auto } ( "auto" uses the container runtime found in the order: "docker", "containerd", "crio" )`)
	option.BindEnv(option.ContainerRuntime)

	flags.Var(option.NewNamedMapOptions(option.ContainerRuntimeEndpoint, &option.Config.ContainerRuntimeEndpoint, nil),
		option.ContainerRuntimeEndpoint, `Container runtime(s) endpoint(s). (default: `+workloads.GetDefaultEPOptsStringWithPrefix("--container-runtime-endpoint=")+`)`)
	option.BindEnv(option.ContainerRuntimeEndpoint)

	flags.BoolP(option.DebugArg, "D", false, "Enable debugging mode")
	option.BindEnv(option.DebugArg)

	flags.StringSlice(option.DebugVerbose, []string{}, "List of enabled verbose debug groups")
	option.BindEnv(option.DebugVerbose)

	flags.StringP(option.Device, "d", "undefined", "Device facing cluster/external network for direct L3 (non-overlay mode)")
	option.BindEnv(option.Device)

	flags.String(option.DatapathMode, defaults.DatapathMode, "Datapath mode name")
	option.BindEnv(option.DatapathMode)

	flags.StringP(option.IpvlanMasterDevice, "", "undefined", "Device facing external network acting as ipvlan master")
	option.BindEnv(option.IpvlanMasterDevice)

	flags.Bool(option.DisableConntrack, false, "Disable connection tracking")
	option.BindEnv(option.DisableConntrack)

	flags.Bool(option.LegacyDisableIPv4Name, false, "Disable IPv4 mode")
	flags.MarkHidden(option.LegacyDisableIPv4Name)
	option.BindEnv(option.LegacyDisableIPv4Name)

	flags.Bool(option.EnableIPv4Name, defaults.EnableIPv4, "Enable IPv4 support")
	option.BindEnv(option.EnableIPv4Name)

	flags.Bool(option.EnableIPv6Name, defaults.EnableIPv6, "Enable IPv6 support")
	option.BindEnv(option.EnableIPv6Name)

	flags.Bool(option.DisableCiliumEndpointCRDName, false, "Disable use of CiliumEndpoint CRD")
	option.BindEnv(option.DisableCiliumEndpointCRDName)

	flags.Bool(option.DisableK8sServices, false, "Disable east-west K8s load balancing by cilium")
	option.BindEnv(option.DisableK8sServices)

	flags.StringP(option.Docker, "e", workloads.GetRuntimeDefaultOpt(workloads.Docker, "endpoint"), "Path to docker runtime socket (DEPRECATED: use container-runtime-endpoint instead)")
	option.BindEnv(option.Docker)

	flags.Bool(option.EnableAutoDirectRoutingName, defaults.EnableAutoDirectRouting, "Enable automatic L2 routing between nodes")
	option.BindEnv(option.EnableAutoDirectRoutingName)

	flags.String(option.EnablePolicy, option.DefaultEnforcement, "Enable policy enforcement")
	option.BindEnv(option.EnablePolicy)

	flags.Bool(option.EnableTracing, false, "Enable tracing while determining policy (debugging)")
	option.BindEnv(option.EnableTracing)

	flags.String(option.EnvoyLog, "", "Path to a separate Envoy log file, if any")
	option.BindEnv(option.EnvoyLog)

	flags.Bool(option.EnableIPSecName, defaults.EnableIPSec, "Enable IPSec support")
	option.BindEnv(option.EnableIPSecName)

	flags.StringVar(&option.Config.IPSecKeyFile, option.IPSecKeyFileName, "", "Path to IPSec key file")

	flags.String(option.HTTP403Message, "", "Message returned in proxy L7 403 body")
	flags.MarkHidden(option.HTTP403Message)
	option.BindEnv(option.HTTP403Message)

	flags.Uint(option.HTTPRequestTimeout, 60*60, "Time after which a forwarded HTTP request is considered failed unless completed (in seconds); Use 0 for unlimited")
	option.BindEnv(option.HTTPRequestTimeout)

	flags.Uint(option.HTTPIdleTimeout, 0, "Time after which a non-gRPC HTTP stream is considered failed unless traffic in the stream has been processed (in seconds); defaults to 0 (unlimited)")
	option.BindEnv(option.HTTPIdleTimeout)

	flags.Uint(option.HTTPMaxGRPCTimeout, 0, "Time after which a forwarded gRPC request is considered failed unless completed (in seconds). A \"grpc-timeout\" header may override this with a shorter value; defaults to 0 (unlimited)")
	option.BindEnv(option.HTTPMaxGRPCTimeout)

	flags.Uint(option.HTTPRetryCount, 3, "Number of retries performed after a forwarded request attempt fails")
	option.BindEnv(option.HTTPRetryCount)

	flags.Uint(option.HTTPRetryTimeout, 0, "Time after which a forwarded but uncompleted request is retried (connection failures are retried immediately); defaults to 0 (never)")
	option.BindEnv(option.HTTPRetryTimeout)

	flags.Uint(option.ProxyConnectTimeout, 1, "Time after which a TCP connect attempt is considered failed unless completed (in seconds)")
	option.BindEnv(option.ProxyConnectTimeout)

	flags.Bool(option.DisableEnvoyVersionCheck, false, "Do not perform Envoy binary version check on startup")
	flags.MarkHidden(option.DisableEnvoyVersionCheck)
	option.BindEnv(option.DisableEnvoyVersionCheck)
	// Disable version check if Envoy build is disabled
	// This needs to be set manually for backward compatibility
	viper.BindEnv(option.DisableEnvoyVersionCheck, "CILIUM_DISABLE_ENVOY_BUILD")

	flags.Var(option.NewNamedMapOptions(option.FixedIdentityMapping, &option.Config.FixedIdentityMapping, option.Config.FixedIdentityMappingValidator),
		option.FixedIdentityMapping, "Key-value for the fixed identity mapping which allows to use reserved label for fixed identities")
	option.BindEnv(option.FixedIdentityMapping)

	flags.Int(option.IPv4ClusterCIDRMaskSize, 8, "Mask size for the cluster wide CIDR")
	option.BindEnv(option.IPv4ClusterCIDRMaskSize)

	flags.String(option.IPv4Range, AutoCIDR, "Per-node IPv4 endpoint prefix, e.g. 10.16.0.0/16")
	option.BindEnv(option.IPv4Range)

	flags.String(option.IPv6Range, AutoCIDR, "Per-node IPv6 endpoint prefix, must be /96, e.g. fd02:1:1::/96")
	option.BindEnv(option.IPv6Range)

	flags.String(option.IPv6ClusterAllocCIDRName, defaults.IPv6ClusterAllocCIDR, "IPv6 /64 CIDR used to allocate per node endpoint /96 CIDR")
	option.BindEnv(option.IPv6ClusterAllocCIDRName)

	flags.String(option.IPv4ServiceRange, AutoCIDR, "Kubernetes IPv4 services CIDR if not inside cluster prefix")
	option.BindEnv(option.IPv4ServiceRange)

	flags.String(option.IPv6ServiceRange, AutoCIDR, "Kubernetes IPv6 services CIDR if not inside cluster prefix")
	option.BindEnv(option.IPv6ServiceRange)

	flags.String(option.K8sAPIServer, "", "Kubernetes api address server (for https use --k8s-kubeconfig-path instead)")
	option.BindEnv(option.K8sAPIServer)

	flags.String(option.K8sKubeConfigPath, "", "Absolute path of the kubernetes kubeconfig file")
	option.BindEnv(option.K8sKubeConfigPath)

	option.BindEnv(option.K8sLegacyHostAllowsWorld)
	// This needs to be set manually for backward compatibility
	viper.BindEnv(option.K8sLegacyHostAllowsWorld, "CILIUM_LEGACY_HOST_ALLOWS_WORLD")

	flags.String(option.K8sNamespaceName, "", "Name of the Kubernetes namespace in which Cilium is deployed in")
	flags.MarkHidden(option.K8sNamespaceName)
	option.BindEnv(option.K8sNamespaceName)

	flags.Bool(option.K8sRequireIPv4PodCIDRName, false, "Require IPv4 PodCIDR to be specified in node resource")
	option.BindEnv(option.K8sRequireIPv4PodCIDRName)

	flags.Bool(option.K8sRequireIPv6PodCIDRName, false, "Require IPv6 PodCIDR to be specified in node resource")
	option.BindEnv(option.K8sRequireIPv6PodCIDRName)

	flags.Bool(option.KeepConfig, false, "When restoring state, keeps containers' configuration in place")
	option.BindEnv(option.KeepConfig)

	flags.Bool(option.KeepBPFTemplates, false, "Do not restore BPF template files from binary")
	option.BindEnv(option.KeepBPFTemplates)

	flags.String(option.KVStore, "", "Key-value store type")
	option.BindEnv(option.KVStore)

	flags.Var(option.NewNamedMapOptions(option.KVStoreOpt, &option.Config.KVStoreOpt, nil),
		option.KVStoreOpt, "Key-value store options")
	option.BindEnv(option.KVStoreOpt)

	flags.String(option.LabelPrefixFile, "", "Valid label prefixes file path")
	option.BindEnv(option.LabelPrefixFile)

	flags.StringSlice(option.Labels, []string{}, "List of label prefixes used to determine identity of an endpoint")
	option.BindEnv(option.Labels)

	flags.String(option.LB, "", "Enables load balancer mode where load balancer bpf program is attached to the given interface")
	option.BindEnv(option.LB)

	flags.String(option.LibDir, defaults.LibraryPath, "Directory path to store runtime build environment")
	option.BindEnv(option.LibDir)

	flags.StringSlice(option.LogDriver, []string{}, "Logging endpoints to use for example syslog")
	option.BindEnv(option.LogDriver)

	flags.Var(option.NewNamedMapOptions(option.LogOpt, &option.Config.LogOpt, nil),
		option.LogOpt, "Log driver options for cilium")
	option.BindEnv(option.LogOpt)

	flags.Bool(option.LogSystemLoadConfigName, false, "Enable periodic logging of system load")
	option.BindEnv(option.LogSystemLoadConfigName)

	flags.String(option.NAT46Range, defaults.DefaultNAT46Prefix, "IPv6 prefix to map IPv4 addresses to")
	option.BindEnv(option.NAT46Range)

	flags.Bool(option.Masquerade, true, "Masquerade packets from endpoints leaving the host")
	option.BindEnv(option.Masquerade)

	flags.Bool(option.InstallIptRules, true, "Install base iptables rules for cilium to mainly interact with kube-proxy (and masquerading)")
	option.BindEnv(option.InstallIptRules)

	flags.Int(option.MaxCtrlIntervalName, 0, "Maximum interval (in seconds) between controller runs. Zero is no limit.")
	flags.MarkHidden(option.MaxCtrlIntervalName)
	option.BindEnv(option.MaxCtrlIntervalName)

	flags.String(option.MonitorAggregationName, "None",
		"Level of monitor aggregation for traces from the datapath")
	option.BindEnv(option.MonitorAggregationName)
	// Leave for backwards compatibility
	viper.BindEnv(option.MonitorAggregationName, "CILIUM_MONITOR_AGGREGATION_LEVEL")

	flags.Int(option.MonitorQueueSizeName, defaults.MonitorQueueSize,
		"Size of the event queue when reading monitor events")
	option.BindEnv(option.MonitorQueueSizeName)

	flags.Int(option.MTUName, 0, "Overwrite auto-detected MTU of underlying network")
	option.BindEnv(option.MTUName)

	flags.Bool(option.PrependIptablesChainsName, true, "Prepend custom iptables chains instead of appending")
	// Leave for backwards compatibility
	viper.BindEnv(option.PrependIptablesChainsName, "CILIUM_PREPEND_IPTABLES_CHAIN")
	option.BindEnv(option.PrependIptablesChainsName)

	flags.String(option.IPv6NodeAddr, "auto", "IPv6 address of node")
	option.BindEnv(option.IPv6NodeAddr)

	flags.String(option.IPv4NodeAddr, "auto", "IPv4 address of node")
	option.BindEnv(option.IPv4NodeAddr)

	flags.Bool(option.Restore, true, "Restores state, if possible, from previous daemon")
	option.BindEnv(option.Restore)

	flags.Bool(option.SidecarHTTPProxy, false, "Disable host HTTP proxy, assuming proxies in sidecar containers")
	flags.MarkHidden(option.SidecarHTTPProxy)
	option.BindEnv(option.SidecarHTTPProxy)

	flags.String(option.SidecarIstioProxyImage, k8s.DefaultSidecarIstioProxyImageRegexp,
		"Regular expression matching compatible Istio sidecar istio-proxy container image names")
	option.BindEnv(option.SidecarIstioProxyImage)

	flags.Bool(option.SingleClusterRouteName, false,
		"Use a single cluster route instead of per node routes")
	option.BindEnv(option.SingleClusterRouteName)

	flags.String(option.SocketPath, defaults.SockPath, "Sets daemon's socket path to listen for connections")
	option.BindEnv(option.SocketPath)

	flags.String(option.StateDir, defaults.RuntimePath, "Directory path to store runtime state")
	option.BindEnv(option.StateDir)

	flags.StringP(option.TunnelName, "t", "", fmt.Sprintf("Tunnel mode {%s} (default \"vxlan\" for the \"veth\" datapath mode)", option.GetTunnelModes()))
	option.BindEnv(option.TunnelName)

	flags.Int(option.TracePayloadlen, 128, "Length of payload to capture when tracing")
	option.BindEnv(option.TracePayloadlen)

	flags.Bool(option.Version, false, "Print version information")
	option.BindEnv(option.Version)

	flags.String(option.FlannelMasterDevice, "",
		"Installs a BPF program to allow for policy enforcement in the given network interface. "+
			"Allows to run Cilium on top of other CNI plugins that provide networking, "+
			"e.g. flannel, where for flannel, this value should be set with 'cni0'. [EXPERIMENTAL]")
	option.BindEnv(option.FlannelMasterDevice)

	flags.Bool(option.FlannelUninstallOnExit, false, fmt.Sprintf("When used along the %s "+
		"flag, it cleans up all BPF programs installed when Cilium agent is terminated.", option.FlannelMasterDevice))
	option.BindEnv(option.FlannelUninstallOnExit)

	flags.Bool(option.FlannelManageExistingContainers, false,
		fmt.Sprintf("Installs a BPF program to allow for policy enforcement in already running containers managed by Flannel."+
			" Require Cilium to be running in the hostPID."))
	option.BindEnv(option.FlannelManageExistingContainers)

	flags.Bool(option.PProf, false, "Enable serving the pprof debugging API")
	option.BindEnv(option.PProf)

	flags.String(option.PrefilterDevice, "undefined", "Device facing external network for XDP prefiltering")
	option.BindEnv(option.PrefilterDevice)

	flags.String(option.PrefilterMode, option.ModePreFilterNative, "Prefilter mode { "+option.ModePreFilterNative+" | "+option.ModePreFilterGeneric+" } (default: "+option.ModePreFilterNative+")")
	option.BindEnv(option.PrefilterMode)

	flags.Bool(option.PreAllocateMapsName, defaults.PreAllocateMaps, "Enable BPF map pre-allocation")
	option.BindEnv(option.PreAllocateMapsName)

	// We expect only one of the possible variables to be filled. The evaluation order is:
	// --prometheus-serve-addr, CILIUM_PROMETHEUS_SERVE_ADDR, then PROMETHEUS_SERVE_ADDR
	// The second environment variable (without the CILIUM_ prefix) is here to
	// handle the case where someone uses a new image with an older spec, and the
	// older spec used the older variable name.
	flags.String(option.PrometheusServeAddr, "", "IP:Port on which to serve prometheus metrics (pass \":Port\" to bind on all interfaces, \"\" is off)")
	viper.BindEnv(option.PrometheusServeAddrDeprecated, "PROMETHEUS_SERVE_ADDR")
	option.BindEnv(option.PrometheusServeAddr)

	flags.Int(option.CTMapEntriesGlobalTCPName, option.CTMapEntriesGlobalTCPDefault, "Maximum number of entries in TCP CT table")
	// Leave for backwards compatibility
	viper.BindEnv(option.CTMapEntriesGlobalTCPName, "CILIUM_GLOBAL_CT_MAX_TCP")
	option.BindEnv(option.CTMapEntriesGlobalTCPName)

	flags.Int(option.CTMapEntriesGlobalAnyName, option.CTMapEntriesGlobalAnyDefault, "Maximum number of entries in non-TCP CT table")
	// Leave for backwards compatibility
	viper.BindEnv(option.CTMapEntriesGlobalAnyName, "CILIUM_GLOBAL_CT_MAX_ANY")
	option.BindEnv(option.CTMapEntriesGlobalAnyName)

	flags.String(option.CMDRef, "", "Path to cmdref output directory")
	flags.MarkHidden(option.CMDRef)
	option.BindEnv(option.CMDRef)

	flags.Int(option.ToFQDNsMinTTL, 0, fmt.Sprintf("The minimum time, in seconds, to use DNS data for toFQDNs policies. (default %d when --tofqdns-enable-poller, %d otherwise)", defaults.ToFQDNsMinTTLPoller, defaults.ToFQDNsMinTTL))
	option.BindEnv(option.ToFQDNsMinTTL)

	flags.Int(option.ToFQDNsProxyPort, 0, "Global port on which the in-agent DNS proxy should listen. Default 0 is a OS-assigned port.")
	option.BindEnv(option.ToFQDNsProxyPort)

	flags.Bool(option.ToFQDNsEnablePoller, false, "Enable proactive polling of DNS names in toFQDNs.matchName rules.")
	option.BindEnv(option.ToFQDNsEnablePoller)

	flags.Bool(option.ToFQDNsEnablePollerEvents, true, "Emit DNS responses seen by the DNS poller as Monitor events, if the poller is enabled.")
	option.BindEnv(option.ToFQDNsEnablePollerEvents)

	flags.StringVar(&option.Config.FQDNRejectResponse, option.FQDNRejectResponseCode, option.FQDNProxyDenyWithRefused, fmt.Sprintf("DNS response code for rejecting DNS requests, available options are '%v'", option.FQDNRejectOptions))
	option.BindEnv(option.FQDNRejectResponseCode)

	flags.Int(option.ToFQDNsMaxIPsPerHost, defaults.ToFQDNsMaxIPsPerHost, "Maximum number of IPs to maintain per FQDN name for each endpoint")
	option.BindEnv(option.ToFQDNsMaxIPsPerHost)

	flags.String(option.ToFQDNsPreCache, defaults.ToFQDNsPreCache, "DNS cache data at this path is preloaded on agent startup")
	option.BindEnv(option.ToFQDNsPreCache)

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

	if option.Config.ConfigFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(option.Config.ConfigFile)
	}

	viper.SetEnvPrefix("cilium")
	viper.SetConfigName("ciliumd") // name of config file (without extension)
	option.Config.ConfigDir = viper.GetString(option.ConfigDir)
	if option.Config.ConfigDir != "" {
		m, err := option.ReadDirConfig(option.Config.ConfigDir)
		if err != nil {
			log.Warnf("Unable to read configuration directory: %s", err)
		} else {
			// replace deprecated fields with new fields
			option.ReplaceDeprecatedFields(m)
			err := option.MergeConfig(m)
			if err != nil {
				log.Fatalf("Unable to merge configuration: %s", err)
			}
		}
	}

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func initEnv(cmd *cobra.Command) {
	// Prepopulate option.Config with options from CLI.
	option.Config.Populate()

	// Logging should always be bootstrapped first. Do not add any code above this!
	logging.SetupLogging(option.Config.LogDriver, option.Config.LogOpt, "cilium-agent", option.Config.Debug)

	if option.Config.CMDRefDir != "" {
		genMarkdown(cmd)
	}

	option.LogRegisteredOptions(log)

	for _, grp := range option.Config.DebugVerbose {
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

	common.RequireRootPrivilege("cilium-agent")

	log.Info("     _ _ _")
	log.Info(" ___|_| |_|_ _ _____")
	log.Info("|  _| | | | | |     |")
	log.Info("|___|_|_|_|___|_|_|_|")
	log.Infof("Cilium %s", version.Version)

	if option.Config.LogSystemLoadConfig {
		loadinfo.StartBackgroundLogger()
	}

	if !option.Config.InstallIptRules {
		option.Config.Masquerade = false
	}

	if option.Config.DisableEnvoyVersionCheck {
		log.Info("Envoy version check disabled")
	} else {
		envoyVersion := envoy.GetEnvoyVersion()
		log.Infof("%s", envoyVersion)

		envoyVersionArray := strings.Fields(envoyVersion)
		if len(envoyVersionArray) < 3 {
			log.Fatal("Truncated Envoy version string, cannot verify version match.")
		}
		// Make sure Envoy version matches ours
		if !strings.HasPrefix(envoyVersionArray[2], envoy.RequiredEnvoyVersionSHA) {
			log.Fatalf("Envoy version %s does not match with required version %s ,aborting.",
				envoyVersionArray[2], envoy.RequiredEnvoyVersionSHA)
		}
	}

	if option.Config.PProf {
		pprof.Enable()
	}

	if option.Config.PreAllocateMaps {
		bpf.EnableMapPreAllocation()
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.Path + ".RunDir": option.Config.RunDir,
		logfields.Path + ".LibDir": option.Config.LibDir,
	})

	if option.Config.LBInterface != "" {
		service.EnableGlobalServiceID(true)
	}

	option.Config.BpfDir = filepath.Join(option.Config.LibDir, defaults.BpfDir)
	scopedLog = scopedLog.WithField(logfields.Path+".BPFDir", defaults.BpfDir)
	if err := os.MkdirAll(option.Config.RunDir, defaults.RuntimePathRights); err != nil {
		scopedLog.WithError(err).Fatal("Could not create runtime directory")
	}

	option.Config.StateDir = filepath.Join(option.Config.RunDir, defaults.StateDir)
	scopedLog = scopedLog.WithField(logfields.Path+".StateDir", option.Config.StateDir)
	if err := os.MkdirAll(option.Config.StateDir, defaults.StateDirRights); err != nil {
		scopedLog.WithError(err).Fatal("Could not create state directory")
	}

	if err := os.MkdirAll(option.Config.LibDir, defaults.RuntimePathRights); err != nil {
		scopedLog.WithError(err).Fatal("Could not create library directory")
	}
	if !option.Config.KeepTemplates {
		if err := RestoreAssets(option.Config.LibDir, defaults.BpfDir); err != nil {
			scopedLog.WithError(err).Fatal("Unable to restore agent assets")
		}
		// Restore permissions of executable files
		if err := RestoreExecPermissions(option.Config.LibDir, `.*\.sh`); err != nil {
			scopedLog.WithError(err).Fatal("Unable to restore agent assets")
		}
	}
	if option.Config.MaxControllerInterval < 0 {
		scopedLog.Fatalf("Invalid %s value %d", option.MaxCtrlIntervalName, option.Config.MaxControllerInterval)
	}

	checkMinRequirements()

	if err := pidfile.Write(defaults.PidFilePath); err != nil {
		log.WithField(logfields.Path, defaults.PidFilePath).WithError(err).Fatal("Failed to create Pidfile")
	}

	option.Config.AllowLocalhost = strings.ToLower(option.Config.AllowLocalhost)
	switch option.Config.AllowLocalhost {
	case option.AllowLocalhostAlways, option.AllowLocalhostAuto, option.AllowLocalhostPolicy:
	default:
		log.Fatalf("Invalid setting for --allow-localhost, must be { %s, %s, %s }",
			option.AllowLocalhostAuto, option.AllowLocalhostAlways, option.AllowLocalhostPolicy)
	}

	option.Config.ModePreFilter = strings.ToLower(option.Config.ModePreFilter)
	switch option.Config.ModePreFilter {
	case option.ModePreFilterNative:
		option.Config.ModePreFilter = "xdpdrv"
	case option.ModePreFilterGeneric:
		option.Config.ModePreFilter = "xdpgeneric"
	default:
		log.Fatalf("Invalid setting for --prefilter-mode, must be { %s, %s }",
			option.ModePreFilterNative, option.ModePreFilterGeneric)
	}

	scopedLog = log.WithField(logfields.Path, option.Config.SocketPath)
	socketDir := path.Dir(option.Config.SocketPath)
	if err := os.MkdirAll(socketDir, defaults.RuntimePathRights); err != nil {
		scopedLog.WithError(err).Fatal("Cannot mkdir directory for cilium socket")
	}

	if err := os.Remove(option.Config.SocketPath); !os.IsNotExist(err) && err != nil {
		scopedLog.WithError(err).Fatal("Cannot remove existing Cilium sock")
	}

	// The standard operation is to mount the BPF filesystem to the
	// standard location (/sys/fs/bpf). The user may chose to specify
	// the path to an already mounted filesystem instead. This is
	// useful if the daemon is being round inside a namespace and the
	// BPF filesystem is mapped into the slave namespace.
	bpf.CheckOrMountFS(option.Config.BPFRoot)
	sockops.CheckOrMountCgrpFS(option.Config.CGroupRoot)

	option.Config.Opts.SetBool(option.Debug, option.Config.Debug)
	option.Config.Opts.SetBool(option.DebugLB, option.Config.Debug)
	option.Config.Opts.SetBool(option.DropNotify, true)
	option.Config.Opts.SetBool(option.TraceNotify, true)
	option.Config.Opts.SetBool(option.PolicyTracing, option.Config.EnableTracing)
	option.Config.Opts.SetBool(option.Conntrack, !option.Config.DisableConntrack)
	option.Config.Opts.SetBool(option.ConntrackAccounting, !option.Config.DisableConntrack)
	option.Config.Opts.SetBool(option.ConntrackLocal, false)

	monitorAggregationLevel, err := option.ParseMonitorAggregationLevel(option.Config.MonitorAggregation)
	if err != nil {
		log.WithError(err).Fatalf("Failed to parse %s: %s",
			option.MonitorAggregationName, err)
	}
	option.Config.Opts.SetValidated(option.MonitorAggregation, monitorAggregationLevel)

	policy.SetPolicyEnabled(option.Config.EnablePolicy)

	if err := cache.AddUserDefinedNumericIdentitySet(option.Config.FixedIdentityMapping); err != nil {
		log.Fatalf("Invalid fixed identities provided: %s", err)
	}

	if !option.Config.EnableIPv4 && !option.Config.EnableIPv6 {
		log.Fatal("Either IPv4 or IPv6 addressing must be enabled")
	}
	if err := kvstore.Setup(option.Config.KVStore, option.Config.KVStoreOpt); err != nil {
		addrkey := fmt.Sprintf("%s.address", option.Config.KVStore)
		addr := option.Config.KVStoreOpt[addrkey]

		log.WithError(err).WithFields(logrus.Fields{
			"kvstore": option.Config.KVStore,
			"address": addr,
		}).Fatal("Unable to setup kvstore")
	}

	if err := labels.ParseLabelPrefixCfg(option.Config.Labels, option.Config.LabelPrefixFile); err != nil {
		log.WithError(err).Fatal("Unable to parse Label prefix configuration")
	}

	_, r, err := net.ParseCIDR(option.Config.NAT46Range)
	if err != nil {
		log.WithError(err).WithField(logfields.V6Prefix, option.Config.NAT46Range).Fatal("Invalid NAT46 prefix")
	}

	option.Config.NAT46Prefix = r

	switch option.Config.DatapathMode {
	case option.DatapathModeVeth:
		if name := viper.GetString(option.IpvlanMasterDevice); name != "undefined" {
			log.WithField(logfields.IpvlanMasterDevice, name).
				Fatal("ipvlan master device cannot be set in the 'veth' datapath mode")
		}
		if option.Config.Tunnel == "" {
			option.Config.Tunnel = option.TunnelVXLAN
		}
		if option.Config.IsFlannelMasterDeviceSet() && option.Config.Tunnel != option.TunnelDisabled {
			log.Warnf("Running Cilium in flannel mode requires tunnel mode be '%s'. Changing tunnel mode to: %s", option.TunnelDisabled, option.TunnelDisabled)
			option.Config.Tunnel = option.TunnelDisabled
		}
	case option.DatapathModeIpvlan:
		if option.Config.Tunnel != "" && option.Config.Tunnel != option.TunnelDisabled {
			log.WithField(logfields.Tunnel, option.Config.Tunnel).
				Fatal("tunnel cannot be set in the 'ipvlan' datapath mode")
		}
		if option.Config.Device != "undefined" {
			log.WithField(logfields.Device, option.Config.Device).
				Fatal("device cannot be set in the 'ipvlan' datapath mode")
		}

		option.Config.Tunnel = option.TunnelDisabled
		// We disallow earlier command line combination of --device with
		// --datapath-mode ipvlan. But given all the remaining logic is
		// shared with option.Config.Device, override it here internally
		// with the specified ipvlan master device. Reason to have a
		// separate, more specific command line parameter here and in
		// the swagger API is that in future we might deprecate --device
		// parameter with e.g. some auto-detection mechanism, thus for
		// ipvlan it is desired to have a separate one, see PR #6608.
		option.Config.Device = viper.GetString(option.IpvlanMasterDevice)
		if option.Config.Device == "undefined" {
			log.WithField(logfields.IpvlanMasterDevice, option.Config.Device).
				Fatal("ipvlan master device must be specified in the 'ipvlan' datapath mode")
		}
		link, err := netlink.LinkByName(option.Config.Device)
		if err != nil {
			log.WithError(err).WithField(logfields.IpvlanMasterDevice, option.Config.Device).
				Fatal("Cannot find device interface")
		}
		option.Config.Ipvlan.MasterDeviceIndex = link.Attrs().Index
		option.Config.Ipvlan.OperationMode = option.OperationModeL3
		if option.Config.InstallIptRules {
			option.Config.Ipvlan.OperationMode = option.OperationModeL3S
		}
	default:
		log.WithField(logfields.DatapathMode, option.Config.DatapathMode).Fatal("Invalid datapath mode")
	}

	// If device has been specified, use it to derive better default
	// allocation prefixes
	if option.Config.Device != "undefined" {
		node.InitDefaultPrefix(option.Config.Device)
	}

	if option.Config.IPv6NodeAddr != "auto" {
		if ip := net.ParseIP(option.Config.IPv6NodeAddr); ip == nil {
			log.WithField(logfields.IPAddr, option.Config.IPv6NodeAddr).Fatal("Invalid IPv6 node address")
		} else {
			if !ip.IsGlobalUnicast() {
				log.WithField(logfields.IPAddr, ip).Fatal("Invalid IPv6 node address: not a global unicast address")
			}

			node.SetIPv6(ip)
		}
	}

	if option.Config.IPv4NodeAddr != "auto" {
		if ip := net.ParseIP(option.Config.IPv4NodeAddr); ip == nil {
			log.WithField(logfields.IPAddr, option.Config.IPv4NodeAddr).Fatal("Invalid IPv4 node address")
		} else {
			node.SetExternalIPv4(ip)
		}
	}

	if option.Config.SidecarHTTPProxy {
		log.Warn(`"sidecar-http-proxy" flag is deprecated and has no effect`)
	}

	k8s.SidecarIstioProxyImageRegexp, err = regexp.Compile(option.Config.SidecarIstioProxyImage)
	if err != nil {
		log.WithError(err).Fatal("Invalid sidecar-istio-proxy-image regular expression")
		return
	}
}

// waitForHostDeviceWhenReady waits the given ifaceName to be up and ready. If
// ifaceName is not found, then it will wait forever until the device is
// created.
func waitForHostDeviceWhenReady(ifaceName string) error {
	for i := 0; ; i++ {
		if i%10 == 0 {
			log.WithField(logfields.Interface, ifaceName).
				Info("Waiting for the underlying interface to be initialized with containers")
		}
		_, err := netlink.LinkByName(ifaceName)
		if err == nil {
			log.WithField(logfields.Interface, ifaceName).
				Info("Underlying interface initialized with containers!")
			break
		}
		select {
		case <-cleanUPSig:
			return errors.New("clean up signal triggered")
		default:
			time.Sleep(time.Second)
		}
	}
	return nil
}

func runDaemon() {
	datapathConfig := linuxdatapath.DatapathConfiguration{
		HostDevice: option.Config.HostDevice,
	}

	log.Info("Initializing daemon")

	// Since flannel doesn't create the cni0 interface until the first container
	// is initialized we need to wait until it is initialized so we can attach
	// the BPF program to it. If Cilium is running as a Kubernetes DaemonSet,
	// there is also a script waiting for the interface to be created.
	if option.Config.IsFlannelMasterDeviceSet() {
		err := waitForHostDeviceWhenReady(option.Config.FlannelMasterDevice)
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.Interface: option.Config.FlannelMasterDevice,
			}).Error("unable to check for host device")
			return
		}
	}

	d, restoredEndpoints, err := NewDaemon(linuxdatapath.NewDatapath(datapathConfig))
	if err != nil {
		log.WithError(err).Fatal("Error while creating daemon")
		return
	}

	// This validation needs to be done outside of the agent until
	// datapath.NodeAddressing is used consistently across the code base.
	log.Info("Validating configured node address ranges")
	if err := node.ValidatePostInit(); err != nil {
		log.WithError(err).Fatal("postinit failed")
	}

	if option.Config.IsFlannelMasterDeviceSet() && option.Config.FlannelUninstallOnExit {
		cleanup.DeferTerminationCleanupFunction(cleanUPWg, cleanUPSig, func() {
			d.compilationMutex.Lock()
			loader.DeleteDatapath(context.Background(), option.FlannelMasterDevice, "egress")
			d.compilationMutex.Unlock()
		})
	}

	log.Info("Starting connection tracking garbage collector")
	endpointmanager.EnableConntrackGC(option.Config.EnableIPv4, option.Config.EnableIPv6,
		option.Config.ConntrackGarbageCollectorInterval,
		restoredEndpoints.restored)

	endpointmanager.EndpointSynchronizer = &endpointsynchronizer.EndpointSynchronizer{}

	log.Info("Launching node monitor daemon")
	go d.nodeMonitor.Run(path.Join(defaults.RuntimePath, defaults.EventsPipe), bpf.GetMapRoot())

	d.initK8sSubsystem()

	if option.Config.RestoreState {
		// When we regenerate restored endpoints, it is guaranteed tha we have
		// received the full list of policies present at the time the daemon
		// is bootstrapped.
		d.regenerateRestoredEndpoints(restoredEndpoints)
		go func() {
			if k8s.IsEnabled() {
				// Start controller which removes any leftover Kubernetes
				// services that may have been deleted while Cilium was not
				// running. Once this controller succeeds, because it has no
				// RunInterval specified, it will not run again unless updated
				// elsewhere. This means that if, for instance, a user manually
				// adds a service via the CLI into the BPF maps, that it will
				// not be cleaned up by the daemon until it restarts.
				controller.NewManager().UpdateController("sync-lb-maps-with-k8s-services",
					controller.ControllerParams{
						DoFunc: func() error {
							return d.syncLBMapsWithK8s()
						},
					},
				)
				return
			}
			if err := d.SyncLBMap(); err != nil {
				log.WithError(err).Warn("Error while recovering endpoints")
			}
		}()
	} else {
		log.Info("No previous state to restore. Cilium will not manage existing containers")
		// We need to read all docker containers so we know we won't
		// going to allocate the same IP addresses and we will ignore
		// these containers from reading.
		workloads.IgnoreRunningWorkloads()
	}

	if option.Config.IsFlannelMasterDeviceSet() {
		// health checking is not supported by flannel
		option.Config.EnableHealthChecking = false

		err := node.SetInternalIPv4From(option.Config.FlannelMasterDevice)
		if err != nil {
			log.WithError(err).WithField("device", option.Config.FlannelMasterDevice).Fatal("Unable to set internal IPv4")
		}
		if option.Config.FlannelManageExistingContainers {
			log.Info("Searching for existing containers...")
			d.attachExistingInfraContainers()
		}
	}

	maps.CollectStaleMapGarbage()
	maps.RemoveDisabledMaps()

	// The workload event listener *must* be enabled *after* restored endpoints
	// are added into the endpoint manager; otherwise, updates to important
	// endpoint metadata, such as Kubernetes pod name and namespace, will not
	// be performed on the endpoint.
	eventsCh, err := workloads.EnableEventListener()
	if err != nil {
		log.WithError(err).Fatal("Error while enabling workload event watcher")
	} else {
		d.workloadsEventsCh = eventsCh
	}

	if option.Config.EnableHealthChecking {
		d.initHealth()
	}

	d.startStatusCollector()

	metricsErrs := initMetrics()

	api := d.instantiateAPI()

	server := server.NewServer(api)
	server.EnabledListeners = []string{"unix"}
	server.SocketPath = flags.Filename(option.Config.SocketPath)
	server.ReadTimeout = apiTimeout
	server.WriteTimeout = apiTimeout
	defer server.Shutdown()

	server.ConfigureAPI()

	repr, err := monitorAPI.TimeRepr(time.Now())
	if err != nil {
		log.WithError(err).Warn("Failed to generate agent start monitor message")
	} else {
		d.SendNotification(monitorAPI.AgentNotifyStart, repr)
	}

	log.WithField("bootstrapTime", time.Since(bootstrapTimestamp)).
		Info("Daemon initialization completed")

	errs := make(chan error, 1)

	go func() {
		errs <- server.Serve()
	}()

	select {
	case err := <-metricsErrs:
		if err != nil {
			log.WithError(err).Fatal("Cannot start metrics server")
		}
	case err := <-errs:
		if err != nil {
			log.WithError(err).Fatal("Error returned from non-returning Serve() call")
		}
	}
}

func (d *Daemon) instantiateAPI() *restapi.CiliumAPI {

	swaggerSpec, err := loads.Analyzed(server.SwaggerJSON, "")
	if err != nil {
		log.WithError(err).Fatal("Cannot load swagger spec")
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

	// /map
	api.DaemonGetMapHandler = NewGetMapHandler(d)
	api.DaemonGetMapNameHandler = NewGetMapNameHandler(d)

	// metrics
	api.MetricsGetMetricsHandler = NewGetMetricsHandler(d)

	// /fqdn/cache
	api.PolicyGetFqdnCacheHandler = NewGetFqdnCacheHandler(d)
	api.PolicyDeleteFqdnCacheHandler = NewDeleteFqdnCacheHandler(d)
	api.PolicyGetFqdnCacheIDHandler = NewGetFqdnCacheIDHandler(d)

	return api
}
