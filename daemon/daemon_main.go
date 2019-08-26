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
	"fmt"
	"io/ioutil"
	"net"
	"os"
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
	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/cleanup"
	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/maps"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s"
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
	"github.com/cilium/cilium/pkg/version"
	"github.com/cilium/cilium/pkg/workloads"

	"github.com/go-openapi/loads"
	gops "github.com/google/gops/agent"
	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
)

const (
	// list of supported verbose debug groups
	argDebugVerboseFlow    = "flow"
	argDebugVerboseKvstore = "kvstore"
	argDebugVerboseEnvoy   = "envoy"

	apiTimeout   = 60 * time.Second
	daemonSubsys = "daemon"

	// fatalSleep is the duration Cilium should sleep before existing in case
	// of a log.Fatal is issued or a CLI flag is specified but does not exist.
	fatalSleep = 2 * time.Second
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, daemonSubsys)

	bootstrapTimestamp = time.Now()

	// RootCmd represents the base command when called without any subcommands
	RootCmd = &cobra.Command{
		Use:   "cilium-agent",
		Short: "Run the cilium agent",
		Run: func(cmd *cobra.Command, args []string) {
			bootstrapStats.earlyInit.Start()
			initEnv(cmd)
			bootstrapStats.earlyInit.End(true)
			runDaemon()
		},
	}

	bootstrapStats = bootstrapStatistics{}
)

func init() {
	RootCmd.SetFlagErrorFunc(func(_ *cobra.Command, e error) error {
		time.Sleep(fatalSleep)
		return e
	})
	logrus.RegisterExitHandler(func() {
		time.Sleep(fatalSleep)
	},
	)
}

func daemonMain() {
	bootstrapStats.overall.Start()

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

func skipInit(basePath string) bool {
	switch basePath {
	case components.CiliumAgentName, components.CiliumDaemonTestName:
		return false
	default:
		return true
	}
}

func init() {
	if skipInit(path.Base(os.Args[0])) {
		log.Debug("Skipping preparation of cilium-agent environment")
		return
	}

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

	flags.Bool(option.AllowICMPFragNeeded, defaults.AllowICMPFragNeeded, "Allow ICMP Fragmentation Needed type packets for purposes like TCP Path MTU.")
	option.BindEnv(option.AllowICMPFragNeeded)

	flags.String(option.AllowLocalhost, option.AllowLocalhostAuto, "Policy when to allow local stack to reach local endpoints { auto | always | policy }")
	option.BindEnv(option.AllowLocalhost)

	flags.Bool(option.AnnotateK8sNode, defaults.AnnotateK8sNode, "Annotate Kubernetes node")
	option.BindEnv(option.AnnotateK8sNode)

	flags.Bool(option.BlacklistConflictingRoutes, defaults.BlacklistConflictingRoutes, "Don't blacklist IP allocations conflicting with local non-cilium routes")
	option.BindEnv(option.BlacklistConflictingRoutes)

	flags.Bool(option.AutoCreateCiliumNodeResource, defaults.AutoCreateCiliumNodeResource, "Automatically create CiliumNode resource for own node on startup")
	option.BindEnv(option.AutoCreateCiliumNodeResource)

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

	flags.Uint(option.ConntrackGarbageCollectorIntervalDeprecated, 0, "Garbage collection interval for the connection tracking table (in seconds)")
	flags.MarkDeprecated(option.ConntrackGarbageCollectorIntervalDeprecated, fmt.Sprintf("please use --%s", option.ConntrackGCInterval))
	option.BindEnv(option.ConntrackGarbageCollectorIntervalDeprecated)

	flags.Duration(option.ConntrackGCInterval, time.Duration(0), "Overwrite the connection-tracking garbage collection interval")
	option.BindEnv(option.ConntrackGCInterval)

	flags.StringSlice(option.ContainerRuntime, option.ContainerRuntimeAuto, `Sets the container runtime(s) used by Cilium { containerd | crio | docker | none | auto } ( "auto" uses the container runtime found in the order: "docker", "containerd", "crio" )`)
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

	flags.Bool(option.EnableEndpointRoutes, defaults.EnableEndpointRoutes, "Use per endpoint routes instead of routing via cilium_host")
	option.BindEnv(option.EnableEndpointRoutes)

	flags.Bool(option.EnableHealthChecking, defaults.EnableHealthChecking, "Enable connectivity health checking")
	option.BindEnv(option.EnableHealthChecking)

	flags.Bool(option.EnableIPv4Name, defaults.EnableIPv4, "Enable IPv4 support")
	option.BindEnv(option.EnableIPv4Name)

	flags.Bool(option.EnableIPv6Name, defaults.EnableIPv6, "Enable IPv6 support")
	option.BindEnv(option.EnableIPv6Name)

	flags.String(option.EncryptInterface, "", "Transparent encryption interface")
	option.BindEnv(option.EncryptInterface)

	flags.Bool(option.EncryptNode, defaults.EncryptNode, "Enables encrypting traffic from non-Cilium pods and host networking")
	option.BindEnv(option.EncryptNode)

	flags.StringSlice(option.IPv4PodSubnets, []string{}, "List of IPv4 pod subnets to preconfigure for encryption")
	option.BindEnv(option.IPv4PodSubnets)

	flags.StringSlice(option.IPv6PodSubnets, []string{}, "List of IPv6 pod subnets to preconfigure for encryption")
	option.BindEnv(option.IPv6PodSubnets)

	flags.String(option.EndpointInterfaceNamePrefix, defaults.EndpointInterfaceNamePrefix, "Prefix of interface name shared by all endpoints")
	option.BindEnv(option.EndpointInterfaceNamePrefix)

	flags.StringSlice(option.ExcludeLocalAddress, []string{}, "Exclude CIDR from being recognized as local address")
	option.BindEnv(option.ExcludeLocalAddress)

	flags.Bool(option.DisableCiliumEndpointCRDName, false, "Disable use of CiliumEndpoint CRD")
	option.BindEnv(option.DisableCiliumEndpointCRDName)

	flags.Bool(option.DisableK8sServices, false, "Disable east-west K8s load balancing by cilium")
	option.BindEnv(option.DisableK8sServices)

	flags.String(option.EgressMasqueradeInterfaces, "", "Limit egress masquerading to interface selector")
	option.BindEnv(option.EgressMasqueradeInterfaces)

	flags.Bool(option.EnableHostReachableServices, false, "Enable reachability of services for host applications (beta)")
	option.BindEnv(option.EnableHostReachableServices)

	flags.StringSlice(option.HostReachableServicesProtos, []string{option.HostServicesTCP, option.HostServicesUDP}, "Only enable reachability of services for host applications for specific protocols")
	option.BindEnv(option.HostReachableServicesProtos)

	flags.Bool(option.DeprecatedEnableLegacyServices, false, "Enable legacy (prior-v1.5) services")
	flags.MarkDeprecated(option.DeprecatedEnableLegacyServices, "this option is deprecated as of v1.6")
	option.BindEnv(option.DeprecatedEnableLegacyServices)

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

	flags.String(option.IPSecKeyFileName, "", "Path to IPSec key file")
	option.BindEnv(option.IPSecKeyFileName)

	flags.Bool(option.ForceLocalPolicyEvalAtSource, defaults.ForceLocalPolicyEvalAtSource, "Force policy evaluation of all local communication at the source endpoint")
	option.BindEnv(option.ForceLocalPolicyEvalAtSource)

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
	// Disable version check if Envoy build is disabled
	option.BindEnvWithLegacyEnvFallback(option.DisableEnvoyVersionCheck, "CILIUM_DISABLE_ENVOY_BUILD")

	flags.Var(option.NewNamedMapOptions(option.FixedIdentityMapping, &option.Config.FixedIdentityMapping, option.Config.FixedIdentityMappingValidator),
		option.FixedIdentityMapping, "Key-value for the fixed identity mapping which allows to use reserved label for fixed identities")
	option.BindEnv(option.FixedIdentityMapping)

	flags.Duration(option.IdentityChangeGracePeriod, defaults.IdentityChangeGracePeriod, "Time to wait before using new identity on endpoint identity change")
	option.BindEnv(option.IdentityChangeGracePeriod)

	flags.String(option.IdentityAllocationMode, option.IdentityAllocationModeKVstore, "Method to use for identity allocation")
	option.BindEnv(option.IdentityAllocationMode)

	flags.String(option.IPAM, "", "Backend to use for IPAM")
	option.BindEnv(option.IPAM)

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

	flags.Bool(option.K8sEventHandover, defaults.K8sEventHandover, "Enable k8s event handover to kvstore for improved scalability")
	option.BindEnv(option.K8sEventHandover)

	flags.String(option.K8sAPIServer, "", "Kubernetes api address server (for https use --k8s-kubeconfig-path instead)")
	option.BindEnv(option.K8sAPIServer)

	flags.String(option.K8sKubeConfigPath, "", "Absolute path of the kubernetes kubeconfig file")
	option.BindEnv(option.K8sKubeConfigPath)

	flags.String(option.K8sNamespaceName, "", "Name of the Kubernetes namespace in which Cilium is deployed in")
	flags.MarkHidden(option.K8sNamespaceName)
	option.BindEnv(option.K8sNamespaceName)

	flags.Bool(option.K8sRequireIPv4PodCIDRName, false, "Require IPv4 PodCIDR to be specified in node resource")
	option.BindEnv(option.K8sRequireIPv4PodCIDRName)

	flags.Bool(option.K8sRequireIPv6PodCIDRName, false, "Require IPv6 PodCIDR to be specified in node resource")
	option.BindEnv(option.K8sRequireIPv6PodCIDRName)

	flags.Uint(option.K8sServiceCacheSize, defaults.K8sServiceCacheSize, "Cilium service cache size for kubernetes")
	option.BindEnv(option.K8sServiceCacheSize)
	flags.MarkHidden(option.K8sServiceCacheSize)

	flags.Bool(option.K8sForceJSONPatch, false, "When set uses JSON Patch to update CNP and CEP status in kube-apiserver")
	option.BindEnv(option.K8sForceJSONPatch)
	flags.MarkHidden(option.K8sForceJSONPatch)

	flags.String(option.K8sWatcherEndpointSelector, defaults.K8sWatcherEndpointSelector, "K8s endpoint watcher will watch for these k8s endpoints")
	option.BindEnv(option.K8sWatcherEndpointSelector)

	flags.Bool(option.KeepConfig, false, "When restoring state, keeps containers' configuration in place")
	option.BindEnv(option.KeepConfig)

	flags.Bool(option.KeepBPFTemplates, false, "Do not restore BPF template files from binary")
	option.BindEnv(option.KeepBPFTemplates)

	flags.String(option.KVStore, "", "Key-value store type")
	option.BindEnv(option.KVStore)

	flags.Duration(option.KVstoreLeaseTTL, defaults.KVstoreLeaseTTL, "Time-to-live for the KVstore lease.")
	flags.MarkHidden(option.KVstoreLeaseTTL)
	option.BindEnv(option.KVstoreLeaseTTL)

	flags.Duration(option.KVstorePeriodicSync, defaults.KVstorePeriodicSync, "Periodic KVstore synchronization interval")
	option.BindEnv(option.KVstorePeriodicSync)

	flags.Duration(option.KVstoreConnectivityTimeout, defaults.KVstoreConnectivityTimeout, "Time after which an incomplete kvstore operation  is considered failed")
	option.BindEnv(option.KVstoreConnectivityTimeout)

	flags.Duration(option.IPAllocationTimeout, defaults.IPAllocationTimeout, "Time after which an incomplete CIDR allocation is considered failed")
	option.BindEnv(option.IPAllocationTimeout)

	flags.Var(option.NewNamedMapOptions(option.KVStoreOpt, &option.Config.KVStoreOpt, nil),
		option.KVStoreOpt, "Key-value store options")
	option.BindEnv(option.KVStoreOpt)

	flags.Uint(option.K8sWatcherQueueSize, 1024, "Queue size used to serialize each k8s event type")
	option.BindEnv(option.K8sWatcherQueueSize)

	flags.String(option.LabelPrefixFile, "", "Valid label prefixes file path")
	option.BindEnv(option.LabelPrefixFile)

	flags.StringSlice(option.Labels, []string{}, "List of label prefixes used to determine identity of an endpoint")
	option.BindEnv(option.Labels)

	flags.String(option.LBDeprecated, "", "Enables load balancer mode where load balancer bpf program is attached to the given interface")
	flags.MarkDeprecated(option.LBDeprecated, "Direct device load-balancing will be deprecated in 1.7")
	option.BindEnv(option.LBDeprecated)

	flags.Bool(option.EnableNodePort, false, "Enable NodePort type services by Cilium (beta)")
	option.BindEnv(option.EnableNodePort)

	flags.StringSlice(option.NodePortRange, []string{fmt.Sprintf("%d", option.NodePortMinDefault), fmt.Sprintf("%d", option.NodePortMaxDefault)}, fmt.Sprintf("Set the min/max NodePort port range"))
	option.BindEnv(option.NodePortRange)

	flags.String(option.LibDir, defaults.LibraryPath, "Directory path to store runtime build environment")
	option.BindEnv(option.LibDir)

	flags.StringSlice(option.LogDriver, []string{}, "Logging endpoints to use for example syslog")
	option.BindEnv(option.LogDriver)

	flags.Var(option.NewNamedMapOptions(option.LogOpt, &option.Config.LogOpt, nil),
		option.LogOpt, "Log driver options for cilium")
	option.BindEnv(option.LogOpt)

	flags.Bool(option.LogSystemLoadConfigName, false, "Enable periodic logging of system load")
	option.BindEnv(option.LogSystemLoadConfigName)

	flags.String(option.LoopbackIPv4, defaults.LoopbackIPv4, "IPv4 address for service loopback SNAT")
	option.BindEnv(option.LoopbackIPv4)

	flags.String(option.NAT46Range, defaults.DefaultNAT46Prefix, "IPv6 prefix to map IPv4 addresses to")
	option.BindEnv(option.NAT46Range)

	flags.Bool(option.Masquerade, true, "Masquerade packets from endpoints leaving the host")
	option.BindEnv(option.Masquerade)

	flags.Bool(option.InstallIptRules, true, "Install base iptables rules for cilium to mainly interact with kube-proxy (and masquerading)")
	option.BindEnv(option.InstallIptRules)

	flags.Int(option.MaxCtrlIntervalName, 0, "Maximum interval (in seconds) between controller runs. Zero is no limit.")
	flags.MarkHidden(option.MaxCtrlIntervalName)
	option.BindEnv(option.MaxCtrlIntervalName)

	flags.StringSlice(option.Metrics, []string{}, "Metrics that should be enabled or disabled from the default metric list. (+metric_foo to enable metric_foo , -metric_bar to disable metric_bar)")
	option.BindEnv(option.Metrics)

	flags.String(option.MonitorAggregationName, "None",
		"Level of monitor aggregation for traces from the datapath")
	option.BindEnvWithLegacyEnvFallback(option.MonitorAggregationName, "CILIUM_MONITOR_AGGREGATION_LEVEL")

	flags.Int(option.MonitorQueueSizeName, 0, "Size of the event queue when reading monitor events")
	option.BindEnv(option.MonitorQueueSizeName)

	flags.Int(option.MTUName, 0, "Overwrite auto-detected MTU of underlying network")
	option.BindEnv(option.MTUName)

	flags.Bool(option.PrependIptablesChainsName, true, "Prepend custom iptables chains instead of appending")
	option.BindEnvWithLegacyEnvFallback(option.PrependIptablesChainsName, "CILIUM_PREPEND_IPTABLES_CHAIN")

	flags.String(option.IPv6NodeAddr, "auto", "IPv6 address of node")
	option.BindEnv(option.IPv6NodeAddr)

	flags.String(option.IPv4NodeAddr, "auto", "IPv4 address of node")
	option.BindEnv(option.IPv4NodeAddr)

	flags.String(option.ReadCNIConfiguration, "", "Read to the CNI configuration at specified path to extract per node configuration")
	option.BindEnv(option.ReadCNIConfiguration)

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
	option.BindEnvWithLegacyEnvFallback(option.PrometheusServeAddr, "PROMETHEUS_SERVE_ADDR")

	flags.Int(option.CTMapEntriesGlobalTCPName, option.CTMapEntriesGlobalTCPDefault, "Maximum number of entries in TCP CT table")
	option.BindEnvWithLegacyEnvFallback(option.CTMapEntriesGlobalTCPName, "CILIUM_GLOBAL_CT_MAX_TCP")

	flags.Int(option.CTMapEntriesGlobalAnyName, option.CTMapEntriesGlobalAnyDefault, "Maximum number of entries in non-TCP CT table")
	option.BindEnvWithLegacyEnvFallback(option.CTMapEntriesGlobalAnyName, "CILIUM_GLOBAL_CT_MAX_ANY")

	flags.Int(option.NATMapEntriesGlobalName, option.NATMapEntriesGlobalDefault, "Maximum number of entries for the global BPF NAT table")
	option.BindEnv(option.NATMapEntriesGlobalName)

	flags.Int(option.PolicyMapEntriesName, defaults.PolicyMapEntries, "Maximum number of entries in endpoint policy map (per endpoint)")
	option.BindEnv(option.PolicyMapEntriesName)

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

	flags.Int(option.PolicyQueueSize, defaults.PolicyQueueSize, "size of queues for policy-related events")
	option.BindEnv(option.PolicyQueueSize)

	flags.Int(option.EndpointQueueSize, defaults.EndpointQueueSize, "size of EventQueue per-endpoint")
	option.BindEnv(option.EndpointQueueSize)

	flags.Bool(option.SelectiveRegeneration, true, "only regenerate endpoints which need to be regenerated upon policy changes")
	flags.MarkHidden(option.SelectiveRegeneration)
	option.BindEnv(option.SelectiveRegeneration)

	flags.Bool(option.SkipCRDCreation, false, "Skip Kubernetes Custom Resource Definitions creations")
	option.BindEnv(option.SkipCRDCreation)

	flags.String(option.WriteCNIConfigurationWhenReady, "", fmt.Sprintf("Write the CNI configuration as specified via --%s to path when agent is ready", option.ReadCNIConfiguration))
	option.BindEnv(option.WriteCNIConfigurationWhenReady)

	flags.Duration(option.PolicyTriggerInterval, defaults.PolicyTriggerInterval, "Time between triggers of policy updates (regenerations for all endpoints)")
	flags.MarkHidden(option.PolicyTriggerInterval)
	option.BindEnv(option.PolicyTriggerInterval)

	flags.Bool(option.DisableCNPStatusUpdates, false, "Do not send CNP NodeStatus updates to the Kubernetes api-server (recommended to run with `cnp-node-status-gc=false` in cilium-operator)")
	option.BindEnv(option.DisableCNPStatusUpdates)

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

	if option.Config.CMDRefDir != "" {
		return
	}

	option.Config.ConfigFile = viper.GetString(option.ConfigFile) // enable ability to specify config file via flag
	option.Config.ConfigDir = viper.GetString(option.ConfigDir)
	viper.SetEnvPrefix("cilium")

	if option.Config.ConfigDir != "" {
		if _, err := os.Stat(option.Config.ConfigDir); os.IsNotExist(err) {
			log.Fatalf("Non-existent configuration directory %s", option.Config.ConfigDir)
		}

		if m, err := option.ReadDirConfig(option.Config.ConfigDir); err != nil {
			log.Fatalf("Unable to read configuration directory %s: %s", option.Config.ConfigDir, err)
		} else {
			// replace deprecated fields with new fields
			option.ReplaceDeprecatedFields(m)
			err := option.MergeConfig(m)
			if err != nil {
				log.Fatalf("Unable to merge configuration: %s", err)
			}
		}
	}

	if option.Config.ConfigFile != "" {
		viper.SetConfigFile(option.Config.ConfigFile)
	} else {
		viper.SetConfigName("ciliumd") // name of config file (without extension)
		viper.AddConfigPath("$HOME")   // adding home directory as first search path
	}

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.WithField(logfields.Path, viper.ConfigFileUsed()).
			Info("Using config from file")
	} else if option.Config.ConfigFile != "" {
		log.WithField(logfields.Path, option.Config.ConfigFile).
			Fatal("Error reading config file")
	} else {
		log.WithField(logfields.Reason, err).Info("Skipped reading configuration file")
	}
}

func initEnv(cmd *cobra.Command) {
	// Prepopulate option.Config with options from CLI.
	option.Config.Populate()

	// add hooks after setting up metrics in the option.Confog
	logging.DefaultLogger.Hooks.Add(metrics.NewLoggingHook(components.CiliumAgentName))

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
		// We need to remove the old probes here as otherwise stale .t tests could
		// still reside from newer Cilium versions which might break downgrade.
		if err := os.RemoveAll(filepath.Join(option.Config.BpfDir, "/probes/")); err != nil {
			scopedLog.WithError(err).Fatal("Could not delete old probes from library directory")
		}
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
	cgroups.CheckOrMountCgrpFS(option.Config.CGroupRoot)

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
		if option.Config.IsFlannelMasterDeviceSet() {
			if option.Config.Tunnel != option.TunnelDisabled {
				log.Warnf("Running Cilium in flannel mode requires tunnel mode be '%s'. Changing tunnel mode to: %s", option.TunnelDisabled, option.TunnelDisabled)
				option.Config.Tunnel = option.TunnelDisabled
			}
			if option.Config.EnableIPv6 {
				log.Warn("Running Cilium in flannel mode requires IPv6 mode be 'false'. Disabling IPv6 mode")
				option.Config.EnableIPv6 = false
			}
			if option.Config.FlannelManageExistingContainers && !option.Config.WorkloadsEnabled() {
				log.Warnf("Managing existing flannel containers with Cilium requires container workloads. Changing %s to %q", option.ContainerRuntime, "auto")
				option.Config.Workloads = option.ContainerRuntimeAuto
			}
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
		if option.Config.EnableIPSec {
			log.Fatal("Currently ipsec cannot be used in the 'ipvlan' datapath mode.")
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

	if option.Config.EnableIPSec && option.Config.Tunnel == option.TunnelDisabled && option.Config.EncryptInterface == "" {
		link, err := linuxdatapath.NodeDeviceNameWithDefaultRoute()
		if err != nil {
			log.Fatal("Ipsec enabled without tunneling but option \"encrypt-interface\" not set and unable to get link for default interface ")
		}
		option.Config.EncryptInterface = link
	}

	// BPF masquerade specified, rejecting unsupported options for this mode.
	if !option.Config.InstallIptRules && option.Config.Masquerade {
		if option.Config.DatapathMode != option.DatapathModeIpvlan {
			log.WithField(logfields.DatapathMode, option.Config.DatapathMode).
				Fatal("BPF masquerade currently only in ipvlan datapath mode (restriction will be lifted soon)")
		}
		if option.Config.Tunnel != option.TunnelDisabled {
			log.WithField(logfields.Tunnel, option.Config.Tunnel).
				Fatal("BPF masquerade only in direct routing mode supported")
		}
		if option.Config.Device == "undefined" {
			log.WithField(logfields.Device, option.Config.Device).
				Fatal("BPF masquerade needs external facing device specified")
		}
	}

	if option.Config.EnableNodePort {
		// We enable host reachable services in order to allow
		// access to node port services from the host.
		option.Config.EnableHostReachableServices = true
		option.Config.EnableHostServicesTCP = true
		option.Config.EnableHostServicesUDP = true
	}

	if option.Config.EnableNodePort && option.Config.Device == "undefined" {
		device, err := linuxdatapath.NodeDeviceNameWithDefaultRoute()
		if err != nil {
			log.Fatal("BPF NodePort's external facing device could not be determined. Use --device to specify.")
		}
		log.WithField(logfields.Interface, device).
			Info("Using auto-derived device for BPF node port")
		option.Config.Device = device
	}

	if option.Config.EnableHostReachableServices {
		if option.Config.EnableHostServicesTCP &&
			(option.Config.EnableIPv4 && bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_INET4_CONNECT) != nil ||
				option.Config.EnableIPv6 && bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_INET6_CONNECT) != nil) {
			log.Fatal("BPF host reachable services for TCP needs kernel 4.17.0 or newer.")
		}
		// NOTE: as host-lb is a hard dependency for NodePort BPF, the following
		//       probe will catch if the fib_lookup helper is missing (< 4.18),
		//       which is another hard dependency for NodePort BPF.
		if option.Config.EnableHostServicesUDP &&
			(option.Config.EnableIPv4 && bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_UDP4_RECVMSG) != nil ||
				option.Config.EnableIPv6 && bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_UDP6_RECVMSG) != nil) {
			log.Fatal("BPF host reachable services for UDP needs kernel 4.19.57, 5.1.16, 5.2.0 or newer. If you run an older kernel and only need TCP, then specify: --host-reachable-services-protos=tcp")
		}
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

func (d *Daemon) initKVStore() {
	goopts := &kvstore.ExtraOptions{
		ClusterSizeDependantInterval: d.nodeDiscovery.Manager.ClusterSizeDependantInterval,
	}

	controller.NewManager().UpdateController("kvstore-locks-gc",
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				kvstore.RunLockGC()
				return nil
			},
			RunInterval: defaults.KVStoreStaleLockTimeout,
		},
	)

	// If K8s is enabled we can do the service translation automagically by
	// looking at services from k8s and retrieve the service IP from that.
	// This makes cilium to not depend on kube dns to interact with etcd
	if k8s.IsEnabled() && kvstore.IsEtcdOperator(option.Config.KVStore, option.Config.KVStoreOpt, option.Config.K8sNamespace) {
		// Wait services and endpoints cache are synced with k8s before setting
		// up etcd so we can perform the name resolution for etcd-operator
		// to the service IP as well perform the service -> backend IPs for
		// that service IP.
		d.waitForCacheSync(k8sAPIGroupServiceV1Core, k8sAPIGroupEndpointV1Core)
		log := log.WithField(logfields.LogSubsys, "etcd")
		goopts.DialOption = []grpc.DialOption{
			grpc.WithDialer(func(s string, duration time.Duration) (conn net.Conn, e error) {
				// If the service is available, do the service translation to
				// the service IP. Otherwise dial with the original service
				// name `s`.
				svc := k8s.ParseServiceIDFrom(s)
				if svc != nil {
					backendIP := d.k8sSvcCache.GetRandomBackendIP(*svc)
					if backendIP != nil {
						s = backendIP.String()
					}
				} else {
					log.Debug("Service not found")
				}
				log.Debugf("custom dialer based on k8s service backend is dialing to %q", s)
				return net.Dial("tcp", s)
			},
			),
		}
	}

	if err := kvstore.Setup(option.Config.KVStore, option.Config.KVStoreOpt, goopts); err != nil {
		addrkey := fmt.Sprintf("%s.address", option.Config.KVStore)
		addr := option.Config.KVStoreOpt[addrkey]

		log.WithError(err).WithFields(logrus.Fields{
			"kvstore": option.Config.KVStore,
			"address": addr,
		}).Fatal("Unable to setup kvstore")
	}
}

func runDaemon() {
	datapathConfig := linuxdatapath.DatapathConfiguration{
		HostDevice:       option.Config.HostDevice,
		EncryptInterface: option.Config.EncryptInterface,
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

	option.Config.RunMonitorAgent = true

	if err := enableIPForwarding(); err != nil {
		log.WithError(err).Fatal("Error when enabling sysctl parameters")
	}

	iptablesManager := &iptables.IptablesManager{}
	iptablesManager.Init()

	d, restoredEndpoints, err := NewDaemon(linuxdatapath.NewDatapath(datapathConfig, iptablesManager), iptablesManager)
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
			d.Datapath().Loader().DeleteDatapath(context.Background(), option.FlannelMasterDevice, "egress")
			d.compilationMutex.Unlock()
		})
	}

	bootstrapStats.enableConntrack.Start()
	log.Info("Starting connection tracking garbage collector")
	d.endpointManager.EnableConntrackGC(option.Config.EnableIPv4, option.Config.EnableIPv6,
		restoredEndpoints.restored)
	bootstrapStats.enableConntrack.End(true)

	bootstrapStats.k8sInit.Start()

	// We need to set up etcd in parallel so we will initialize the k8s
	// subsystem as well in parallel so caches will start to be synchronized
	// with k8s.
	k8sCachesSynced := d.initK8sSubsystem()
	if option.Config.KVStore == "" {
		log.Info("Skipping kvstore configuration")
	} else {
		d.initKVStore()
	}

	// Wait only for certain caches, but not all!
	// (Check Daemon.initK8sSubsystem() for more info)
	<-k8sCachesSynced
	bootstrapStats.k8sInit.End(true)
	restoreComplete := d.initRestore(restoredEndpoints)

	if option.Config.IsFlannelMasterDeviceSet() {
		// health checking is not supported by flannel
		log.Warnf("Running Cilium in flannel mode doesn't support health checking. Changing %s mode to %t", option.EnableHealthChecking, false)
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

	if !option.Config.DryMode {
		go func() {
			if restoreComplete != nil {
				<-restoreComplete
			}
			d.dnsNameManager.CompleteBootstrap()

			ms := maps.NewMapSweeper(&EndpointMapManager{
				EndpointManager: d.endpointManager,
			})
			ms.CollectStaleMapGarbage()
			ms.RemoveDisabledMaps()
		}()
	}

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

	bootstrapStats.healthCheck.Start()
	if option.Config.EnableHealthChecking {
		d.initHealth()
	}
	bootstrapStats.healthCheck.End(true)

	d.startStatusCollector()

	metricsErrs := initMetrics()

	bootstrapStats.initAPI.Start()
	api := d.instantiateAPI()

	server := server.NewServer(api)
	server.EnabledListeners = []string{"unix"}
	server.SocketPath = flags.Filename(option.Config.SocketPath)
	server.ReadTimeout = apiTimeout
	server.WriteTimeout = apiTimeout
	defer server.Shutdown()

	server.ConfigureAPI()
	bootstrapStats.initAPI.End(true)

	repr, err := monitorAPI.TimeRepr(time.Now())
	if err != nil {
		log.WithError(err).Warn("Failed to generate agent start monitor message")
	} else {
		d.SendNotification(monitorAPI.AgentNotifyStart, repr)
	}

	log.WithField("bootstrapTime", time.Since(bootstrapTimestamp)).
		Info("Daemon initialization completed")

	if option.Config.WriteCNIConfigurationWhenReady != "" {
		input, err := ioutil.ReadFile(option.Config.ReadCNIConfiguration)
		if err != nil {
			log.WithError(err).Fatal("Unable to read CNI configuration file")
		}

		if err = ioutil.WriteFile(option.Config.WriteCNIConfigurationWhenReady, input, 0644); err != nil {
			log.WithError(err).Fatalf("Unable to write CNI configuration file to %s", option.Config.WriteCNIConfigurationWhenReady)
		} else {
			log.Infof("Wrote CNI configuration file to %s", option.Config.WriteCNIConfigurationWhenReady)
		}
	}

	errs := make(chan error, 1)

	go func() {
		errs <- server.Serve()
	}()

	bootstrapStats.overall.End(true)
	bootstrapStats.updateMetrics()

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

	// /cluster/nodes
	api.DaemonGetClusterNodesHandler = NewGetClusterNodesHandler(d)

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

	// /identity/endpoints
	api.PolicyGetIdentityEndpointsHandler = newGetIdentityEndpointsIDHandler(d)

	// /policy/
	api.PolicyGetPolicyHandler = newGetPolicyHandler(d)
	api.PolicyPutPolicyHandler = newPutPolicyHandler(d)
	api.PolicyDeletePolicyHandler = newDeletePolicyHandler(d)
	api.PolicyGetPolicySelectorsHandler = newGetPolicyCacheHandler(d)

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
