// Copyright 2016-2020 Authors of Cilium
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
	"math"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/api/v1/server/restapi"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/cleanup"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/datapath/maps"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/identity"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipmasq"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/loadinfo"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/ctmap/gc"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/probe"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/cilium/cilium/pkg/version"
	"github.com/go-openapi/loads"
	gops "github.com/google/gops/agent"
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
			cmdRefDir := viper.GetString(option.CMDRef)
			if cmdRefDir != "" {
				genMarkdown(cmd, cmdRefDir)
				os.Exit(0)
			}
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

// Execute sets up gops, installs the cleanup signal handler and invokes
// the root command. This function only returns when an interrupt
// signal has been received. This is intended to be called by main.main().
func Execute() {
	bootstrapStats.overall.Start()

	// Open socket for using gops to get stacktraces of the agent.
	if err := gops.Listen(gops.Options{}); err != nil {
		errorString := fmt.Sprintf("unable to start gops: %s", err)
		fmt.Println(errorString)
		os.Exit(-1)
	}
	interruptCh := cleaner.registerSigHandler()
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	<-interruptCh
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

	cobra.OnInitialize(option.InitConfig("Cilium", "ciliumd"))

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
	flags.Int(option.AgentHealthPort, defaults.AgentHealthPort, "TCP port for agent health status API")
	option.BindEnv(option.AgentHealthPort)

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

	flags.Bool(option.EnableBPFClockProbe, false, "Enable BPF clock source probing for more efficient tick retrieval")
	option.BindEnv(option.EnableBPFClockProbe)

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

	flags.Duration(option.ConntrackGCInterval, time.Duration(0), "Overwrite the connection-tracking garbage collection interval")
	option.BindEnv(option.ConntrackGCInterval)

	flags.BoolP(option.DebugArg, "D", false, "Enable debugging mode")
	option.BindEnv(option.DebugArg)

	flags.StringSlice(option.DebugVerbose, []string{}, "List of enabled verbose debug groups")
	option.BindEnv(option.DebugVerbose)

	flags.StringSliceP(option.Device, "d", []string{}, "List of devices facing cluster/external network for attaching bpf_netdev (first device should be one used for direct routing if tunneling is disabled)")
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

	flags.StringSlice(option.EndpointStatus, []string{},
		"Enable additional CiliumEndpoint status features ("+strings.Join(option.EndpointStatusValues(), ",")+")")
	option.BindEnv(option.EndpointStatus)

	flags.Bool(option.EnableEndpointHealthChecking, defaults.EnableEndpointHealthChecking, "Enable connectivity health checking between virtual endpoints")
	option.BindEnv(option.EnableEndpointHealthChecking)

	flags.Bool(option.EnableLocalNodeRoute, defaults.EnableLocalNodeRoute, "Enable installation of the route which points the allocation prefix of the local node")
	option.BindEnv(option.EnableLocalNodeRoute)

	flags.Bool(option.EnableIPv4Name, defaults.EnableIPv4, "Enable IPv4 support")
	option.BindEnv(option.EnableIPv4Name)

	flags.Bool(option.EnableIPv6Name, defaults.EnableIPv6, "Enable IPv6 support")
	option.BindEnv(option.EnableIPv6Name)

	flags.Bool(option.EnableRemoteNodeIdentity, defaults.EnableRemoteNodeIdentity, "Enable use of remote node identity")
	option.BindEnv(option.EnableRemoteNodeIdentity)

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
	flags.MarkDeprecated(option.DisableK8sServices, "This option is no longer supported and will be removed in v1.9")

	flags.String(option.EgressMasqueradeInterfaces, "", "Limit egress masquerading to interface selector")
	option.BindEnv(option.EgressMasqueradeInterfaces)

	flags.Bool(option.EnableHostReachableServices, false, "Enable reachability of services for host applications (beta)")
	option.BindEnv(option.EnableHostReachableServices)

	flags.StringSlice(option.HostReachableServicesProtos, []string{option.HostServicesTCP, option.HostServicesUDP}, "Only enable reachability of services for host applications for specific protocols")
	option.BindEnv(option.HostReachableServicesProtos)

	flags.Bool(option.EnableAutoDirectRoutingName, defaults.EnableAutoDirectRouting, "Enable automatic L2 routing between nodes")
	option.BindEnv(option.EnableAutoDirectRoutingName)

	flags.Bool(option.EnableXTSocketFallbackName, defaults.EnableXTSocketFallback, "Enable fallback for missing xt_socket module")
	option.BindEnv(option.EnableXTSocketFallbackName)

	flags.String(option.EnablePolicy, option.DefaultEnforcement, "Enable policy enforcement")
	option.BindEnv(option.EnablePolicy)

	flags.Bool(option.EnableExternalIPs, defaults.EnableExternalIPs, fmt.Sprintf("Enable k8s service externalIPs feature (requires enabling %s)", option.EnableNodePort))
	option.BindEnv(option.EnableExternalIPs)

	flags.Bool(option.K8sEnableEndpointSlice, defaults.K8sEnableEndpointSlice, "Enables k8s EndpointSlice feature in Cilium if the k8s cluster supports it")
	option.BindEnv(option.K8sEnableEndpointSlice)

	flags.Bool(option.K8sEnableAPIDiscovery, defaults.K8sEnableAPIDiscovery, "Enable discovery of Kubernetes API groups and resources with the discovery API")
	option.BindEnv(option.K8sEnableAPIDiscovery)

	flags.Bool(option.EnableL7Proxy, defaults.EnableL7Proxy, "Enable L7 proxy for L7 policy enforcement")
	option.BindEnv(option.EnableL7Proxy)

	flags.Bool(option.EnableTracing, false, "Enable tracing while determining policy (debugging)")
	option.BindEnv(option.EnableTracing)

	flags.Bool(option.EnableWellKnownIdentities, defaults.EnableWellKnownIdentities, "Enable well-known identities for known Kubernetes components")
	option.BindEnv(option.EnableWellKnownIdentities)

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

	flags.String(option.IPAM, ipamOption.IPAMHostScopeLegacy, "Backend to use for IPAM")
	option.BindEnv(option.IPAM)

	flags.Int(option.IPv4ClusterCIDRMaskSize, 8, "Mask size for the cluster wide CIDR")
	option.BindEnv(option.IPv4ClusterCIDRMaskSize)
	flags.MarkDeprecated(option.IPv4ClusterCIDRMaskSize, "This option has been deprecated and will be removed in v1.9")

	flags.String(option.IPv4Range, AutoCIDR, "Per-node IPv4 endpoint prefix, e.g. 10.16.0.0/16")
	option.BindEnv(option.IPv4Range)

	flags.String(option.IPv6Range, AutoCIDR, "Per-node IPv6 endpoint prefix, e.g. fd02:1:1::/96")
	option.BindEnv(option.IPv6Range)

	flags.String(option.IPv6ClusterAllocCIDRName, defaults.IPv6ClusterAllocCIDR, "IPv6 /64 CIDR used to allocate per node endpoint /96 CIDR")
	option.BindEnv(option.IPv6ClusterAllocCIDRName)

	flags.String(option.IPv4ServiceRange, AutoCIDR, "Kubernetes IPv4 services CIDR if not inside cluster prefix")
	option.BindEnv(option.IPv4ServiceRange)

	flags.String(option.IPv6ServiceRange, AutoCIDR, "Kubernetes IPv6 services CIDR if not inside cluster prefix")
	option.BindEnv(option.IPv6ServiceRange)

	flags.Bool(option.K8sEventHandover, defaults.K8sEventHandover, "Enable k8s event handover to kvstore for improved scalability")
	option.BindEnv(option.K8sEventHandover)

	flags.String(option.K8sAPIServer, "", "Kubernetes API server URL")
	option.BindEnv(option.K8sAPIServer)

	flags.String(option.K8sKubeConfigPath, "", "Absolute path of the kubernetes kubeconfig file")
	option.BindEnv(option.K8sKubeConfigPath)

	flags.String(option.K8sNamespaceName, "", "Name of the Kubernetes namespace in which Cilium is deployed in")
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
	flags.MarkDeprecated(option.KeepBPFTemplates, "This option is no longer supported and will be removed in v1.9")

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

	flags.String(option.KubeProxyReplacement, option.KubeProxyReplacementPartial, fmt.Sprintf(
		"auto-enable available features for kube-proxy replacement (%q), "+
			"or enable only selected features (will panic if any selected feature cannot be enabled) (%q) "+
			"or enable all features (will panic if any feature cannot be enabled) (%q), "+
			"or completely disable it (ignores any selected feature) (%q)",
		option.KubeProxyReplacementProbe, option.KubeProxyReplacementPartial,
		option.KubeProxyReplacementStrict, option.KubeProxyReplacementDisabled))
	option.BindEnv(option.KubeProxyReplacement)

	flags.Bool(option.EnableHostPort, true, fmt.Sprintf("Enable k8s hostPort mapping feature (requires enabling %s)", option.EnableNodePort))
	option.BindEnv(option.EnableHostPort)

	flags.Bool(option.EnableNodePort, false, "Enable NodePort type services by Cilium (beta)")
	option.BindEnv(option.EnableNodePort)

	flags.String(option.NodePortMode, option.NodePortModeSNAT, "BPF NodePort mode (\"snat\", \"dsr\", \"hybrid\")")
	option.BindEnv(option.NodePortMode)

	flags.Bool(option.EnableAutoProtectNodePortRange, true,
		"Append NodePort range to net.ipv4.ip_local_reserved_ports if it overlaps "+
			"with ephemeral port range (net.ipv4.ip_local_port_range)")
	option.BindEnv(option.EnableAutoProtectNodePortRange)

	flags.StringSlice(option.NodePortRange, []string{fmt.Sprintf("%d", option.NodePortMinDefault), fmt.Sprintf("%d", option.NodePortMaxDefault)}, "Set the min/max NodePort port range")
	option.BindEnv(option.NodePortRange)

	flags.Bool(option.NodePortBindProtection, true, "Reject application bind(2) requests to service ports in the NodePort range")
	option.BindEnv(option.NodePortBindProtection)

	flags.String(option.NodePortAcceleration, option.NodePortAccelerationNone, "BPF NodePort acceleration via XDP (\"native\", \"none\")")
	option.BindEnv(option.NodePortAcceleration)

	flags.Bool(option.EnableSessionAffinity, false, "Enable support for service session affinity")
	option.BindEnv(option.EnableSessionAffinity)

	flags.Bool(option.EnableHostFirewall, false, "Enable host network policies")
	option.BindEnv(option.EnableHostFirewall)

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

	flags.Bool(option.EnableBPFMasquerade, false, "Masquerade packets from endpoints leaving the host with BPF instead of iptables")
	option.BindEnv(option.EnableBPFMasquerade)

	flags.Bool(option.EnableIPMasqAgent, false, "Enable BPF ip-masq-agent")
	option.BindEnv(option.EnableIPMasqAgent)

	flags.String(option.IPMasqAgentConfigPath, "/etc/config/ip-masq-agent", "ip-masq-agent configuration file path")
	option.BindEnv(option.IPMasqAgentConfigPath)

	flags.Bool(option.InstallIptRules, true, "Install base iptables rules for cilium to mainly interact with kube-proxy (and masquerading)")
	option.BindEnv(option.InstallIptRules)

	flags.Duration(option.IPTablesLockTimeout, 5*time.Second, "Time to pass to each iptables invocation to wait for xtables lock acquisition")
	option.BindEnv(option.IPTablesLockTimeout)

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
	flags.MarkDeprecated(option.FlannelManageExistingContainers, "This option is no longer supported and will be removed in v1.8")

	flags.Bool(option.PProf, false, "Enable serving the pprof debugging API")
	option.BindEnv(option.PProf)

	flags.String(option.PrefilterDevice, "undefined", "Device facing external network for XDP prefiltering")
	option.BindEnv(option.PrefilterDevice)

	flags.String(option.PrefilterMode, option.ModePreFilterNative, "Prefilter mode via XDP (\"native\", \"generic\")")
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

	flags.String(option.CertsDirectory, defaults.CertsDirectory, "Root directory to find certificates specified in L7 TLS policy enforcement")
	option.BindEnv(option.CertsDirectory)

	flags.Int(option.CTMapEntriesGlobalAnyName, option.CTMapEntriesGlobalAnyDefault, "Maximum number of entries in non-TCP CT table")
	option.BindEnvWithLegacyEnvFallback(option.CTMapEntriesGlobalAnyName, "CILIUM_GLOBAL_CT_MAX_ANY")

	flags.Duration(option.CTMapEntriesTimeoutTCPName, 21600*time.Second, "Timeout for established entries in TCP CT table")
	option.BindEnv(option.CTMapEntriesTimeoutTCPName)

	flags.Duration(option.CTMapEntriesTimeoutAnyName, 60*time.Second, "Timeout for entries in non-TCP CT table")
	option.BindEnv(option.CTMapEntriesTimeoutAnyName)

	flags.Duration(option.CTMapEntriesTimeoutSVCTCPName, 21600*time.Second, "Timeout for established service entries in TCP CT table")
	option.BindEnv(option.CTMapEntriesTimeoutSVCTCPName)

	flags.Duration(option.CTMapEntriesTimeoutSVCAnyName, 60*time.Second, "Timeout for service entries in non-TCP CT table")
	option.BindEnv(option.CTMapEntriesTimeoutSVCAnyName)

	flags.Duration(option.CTMapEntriesTimeoutSYNName, 60*time.Second, "Establishment timeout for entries in TCP CT table")
	option.BindEnv(option.CTMapEntriesTimeoutSYNName)

	flags.Duration(option.CTMapEntriesTimeoutFINName, 10*time.Second, "Teardown timeout for entries in TCP CT table")
	option.BindEnv(option.CTMapEntriesTimeoutFINName)

	flags.Duration(option.MonitorAggregationInterval, 5*time.Second, "Monitor report interval when monitor aggregation is enabled")
	option.BindEnv(option.MonitorAggregationInterval)

	flags.StringSlice(option.MonitorAggregationFlags, option.MonitorAggregationFlagsDefault, "TCP flags that trigger monitor reports when monitor aggregation is enabled")
	option.BindEnv(option.MonitorAggregationFlags)

	flags.Int(option.NATMapEntriesGlobalName, option.NATMapEntriesGlobalDefault, "Maximum number of entries for the global BPF NAT table")
	option.BindEnv(option.NATMapEntriesGlobalName)

	flags.Int(option.NeighMapEntriesGlobalName, option.NATMapEntriesGlobalDefault, "Maximum number of entries for the global BPF neighbor table")
	option.BindEnv(option.NeighMapEntriesGlobalName)

	flags.Int(option.PolicyMapEntriesName, defaults.PolicyMapEntries, "Maximum number of entries in endpoint policy map (per endpoint)")
	option.BindEnv(option.PolicyMapEntriesName)

	flags.Float64(option.MapEntriesGlobalDynamicSizeRatioName, 0.0, "Ratio (0.0-1.0) of total system memory to use for dynamic sizing of CT, NAT and policy BPF maps. Set to 0.0 to disable dynamic BPF map sizing (default: 0.0)")
	option.BindEnv(option.MapEntriesGlobalDynamicSizeRatioName)

	flags.String(option.CMDRef, "", "Path to cmdref output directory")
	flags.MarkHidden(option.CMDRef)
	option.BindEnv(option.CMDRef)

	flags.Int(option.ToFQDNsMinTTL, 0, fmt.Sprintf("The minimum time, in seconds, to use DNS data for toFQDNs policies. (default %d )", defaults.ToFQDNsMinTTL))
	option.BindEnv(option.ToFQDNsMinTTL)

	flags.Int(option.ToFQDNsProxyPort, 0, "Global port on which the in-agent DNS proxy should listen. Default 0 is a OS-assigned port.")
	option.BindEnv(option.ToFQDNsProxyPort)

	flags.Bool(option.ToFQDNsEnablePoller, false, "Enable proactive polling of DNS names in toFQDNs.matchName rules.")
	option.BindEnv(option.ToFQDNsEnablePoller)
	flags.MarkDeprecated(option.ToFQDNsEnablePoller, "This option has been deprecated and will be removed in v1.9")

	flags.Bool(option.ToFQDNsEnablePollerEvents, true, "Emit DNS responses seen by the DNS poller as Monitor events, if the poller is enabled.")
	option.BindEnv(option.ToFQDNsEnablePollerEvents)
	flags.MarkDeprecated(option.ToFQDNsEnablePollerEvents, "This option has been deprecated and will be removed in v1.9")

	flags.StringVar(&option.Config.FQDNRejectResponse, option.FQDNRejectResponseCode, option.FQDNProxyDenyWithRefused, fmt.Sprintf("DNS response code for rejecting DNS requests, available options are '%v'", option.FQDNRejectOptions))
	option.BindEnv(option.FQDNRejectResponseCode)

	flags.Int(option.ToFQDNsMaxIPsPerHost, defaults.ToFQDNsMaxIPsPerHost, "Maximum number of IPs to maintain per FQDN name for each endpoint")
	option.BindEnv(option.ToFQDNsMaxIPsPerHost)

	flags.Int(option.ToFQDNsMaxDeferredConnectionDeletes, defaults.ToFQDNsMaxDeferredConnectionDeletes, "Maximum number of IPs to retain for expired DNS lookups with still-active connections")
	option.BindEnv(option.ToFQDNsMaxDeferredConnectionDeletes)

	flags.DurationVar(&option.Config.FQDNProxyResponseMaxDelay, option.FQDNProxyResponseMaxDelay, 100*time.Millisecond, "The maximum time the DNS proxy holds an allowed DNS response before sending it along. Responses are sent as soon as the datapath is updated with the new IP information.")
	option.BindEnv(option.FQDNProxyResponseMaxDelay)

	flags.String(option.ToFQDNsPreCache, defaults.ToFQDNsPreCache, "DNS cache data at this path is preloaded on agent startup")
	option.BindEnv(option.ToFQDNsPreCache)

	flags.Bool(option.ToFQDNsEnableDNSCompression, defaults.ToFQDNsEnableDNSCompression, "Allow the DNS proxy to compress responses to endpoints that are larger than 512 Bytes or the EDNS0 option, if present")
	option.BindEnv(option.ToFQDNsEnableDNSCompression)

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

	flags.Bool(option.DisableCNPStatusUpdates, false, `Do not send CNP NodeStatus updates to the Kubernetes api-server (recommended to run with "cnp-node-status-gc=false" in cilium-operator)`)
	option.BindEnv(option.DisableCNPStatusUpdates)

	flags.Bool(option.PolicyAuditModeArg, false, "Enable policy audit (non-drop) mode")
	option.BindEnv(option.PolicyAuditModeArg)

	flags.Bool(option.EnableHubble, false, "Enable hubble server")
	option.BindEnv(option.EnableHubble)

	flags.String(option.HubbleSocketPath, defaults.HubbleSockPath, "Set hubble's socket path to listen for connections")
	option.BindEnv(option.HubbleSocketPath)

	flags.String(option.HubbleListenAddress, "", `An additional address for Hubble server to listen to, e.g. ":4244"`)
	option.BindEnv(option.HubbleListenAddress)

	flags.Int(option.HubbleFlowBufferSize, 4095, "Maximum number of flows in Hubble's buffer. The actual buffer size gets rounded up to the next power of 2, e.g. 4095 => 4096")
	option.BindEnv(option.HubbleFlowBufferSize)

	flags.Int(option.HubbleEventQueueSize, 0, "Buffer size of the channel to receive monitor events.")
	option.BindEnv(option.HubbleEventQueueSize)

	flags.String(option.HubbleMetricsServer, "", "Address to serve Hubble metrics on.")
	option.BindEnv(option.HubbleMetricsServer)

	flags.StringSlice(option.HubbleMetrics, []string{}, "List of Hubble metrics to enable.")
	option.BindEnv(option.HubbleMetrics)

	flags.StringSlice(option.DisableIptablesFeederRules, []string{}, "Chains to ignore when installing feeder rules.")
	option.BindEnv(option.DisableIptablesFeederRules)

	flags.Duration(option.K8sHeartbeatTimeout, 30*time.Second, "Configures the timeout for api-server heartbeat, set to 0 to disable")
	option.BindEnv(option.K8sHeartbeatTimeout)

	flags.Bool(option.EnableIPv4FragmentsTrackingName, defaults.EnableIPv4FragmentsTracking, "Enable IPv4 fragments tracking for L4-based lookups")
	option.BindEnv(option.EnableIPv4FragmentsTrackingName)

	flags.Int(option.FragmentsMapEntriesName, defaults.FragmentsMapEntries, "Maximum number of entries in fragments tracking map")
	option.BindEnv(option.FragmentsMapEntriesName)

	viper.BindPFlags(flags)

	CustomCommandHelpFormat(RootCmd, option.HelpFlagSections)

	// Reset the help function to also exit, as we block elsewhere in interrupts
	// and would not exit when called with -h.
	ResetHelpandExit(RootCmd)
}

// restoreExecPermissions restores file permissions to 0740 of all files inside
// `searchDir` with the given regex `patterns`.
func restoreExecPermissions(searchDir string, patterns ...string) error {
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

func initEnv(cmd *cobra.Command) {
	option.Config.SetMapElementSizes(
		// for the conntrack and NAT element size we assume the largest possible
		// key size, i.e. IPv6 keys
		ctmap.SizeofCtKey6Global+ctmap.SizeofCtEntry,
		nat.SizeofNatKey6+nat.SizeofNatEntry6,
		policymap.SizeofPolicyKey+policymap.SizeofPolicyEntry)

	// Prepopulate option.Config with options from CLI.
	option.Config.Populate()

	// add hooks after setting up metrics in the option.Confog
	logging.DefaultLogger.Hooks.Add(metrics.NewLoggingHook(components.CiliumAgentName))

	// Logging should always be bootstrapped first. Do not add any code above this!
	logging.SetupLogging(option.Config.LogDriver, logging.LogOptions(option.Config.LogOpt), "cilium-agent", option.Config.Debug)

	option.LogRegisteredOptions(log)

	// Configure k8s as soon as possible so that k8s.IsEnabled() has the right
	// behavior.
	bootstrapStats.k8sInit.Start()
	k8s.Configure(option.Config.K8sAPIServer, option.Config.K8sKubeConfigPath, defaults.K8sClientQPSLimit, defaults.K8sClientBurst)
	bootstrapStats.k8sInit.End(true)

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

	// This check is here instead of in DaemonConfig.Populate (invoked at the
	// start of this function as option.Config.Populate) to avoid an import loop.
	if option.Config.IdentityAllocationMode == option.IdentityAllocationModeCRD && !k8s.IsEnabled() {
		log.Fatal("CRD Identity allocation mode requires k8s to be configured.")
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
	// Restore permissions of executable files
	if err := restoreExecPermissions(option.Config.LibDir, `.*\.sh`); err != nil {
		scopedLog.WithError(err).Fatal("Unable to restore agent asset permissions")
	}

	if option.Config.MaxControllerInterval < 0 {
		scopedLog.Fatalf("Invalid %s value %d", option.MaxCtrlIntervalName, option.Config.MaxControllerInterval)
	}

	linuxdatapath.CheckMinRequirements()

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
	if option.Config.ModePreFilter == "generic" {
		option.Config.ModePreFilter = option.ModePreFilterGeneric
	}
	if option.Config.ModePreFilter != option.ModePreFilterNative &&
		option.Config.ModePreFilter != option.ModePreFilterGeneric {
		log.Fatalf("Invalid setting for --prefilter-mode, must be { %s, generic }",
			option.ModePreFilterNative)
	}

	if option.Config.DevicePreFilter != "undefined" {
		if option.Config.XDPDevice != "undefined" &&
			option.Config.XDPDevice != option.Config.DevicePreFilter {
			log.Fatalf("Cannot set Prefilter device: mismatch between NodePort device %s and Prefilter device %s",
				option.Config.XDPDevice, option.Config.DevicePreFilter)
		}

		option.Config.XDPDevice = option.Config.DevicePreFilter
		if err := loader.SetXDPMode(option.Config.ModePreFilter); err != nil {
			scopedLog.WithError(err).Fatal("Cannot set prefilter XDP mode")
		}
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
	bpf.CheckOrMountFS(option.Config.BPFRoot, k8s.IsEnabled())
	cgroups.CheckOrMountCgrpFS(option.Config.CGroupRoot)

	option.Config.Opts.SetBool(option.Debug, option.Config.Debug)
	option.Config.Opts.SetBool(option.DebugLB, option.Config.Debug)
	option.Config.Opts.SetBool(option.DropNotify, true)
	option.Config.Opts.SetBool(option.TraceNotify, true)
	option.Config.Opts.SetBool(option.PolicyVerdictNotify, true)
	option.Config.Opts.SetBool(option.PolicyTracing, option.Config.EnableTracing)
	option.Config.Opts.SetBool(option.Conntrack, !option.Config.DisableConntrack)
	option.Config.Opts.SetBool(option.ConntrackAccounting, !option.Config.DisableConntrack)
	option.Config.Opts.SetBool(option.ConntrackLocal, false)
	option.Config.Opts.SetBool(option.PolicyAuditMode, option.Config.PolicyAuditMode)

	monitorAggregationLevel, err := option.ParseMonitorAggregationLevel(option.Config.MonitorAggregation)
	if err != nil {
		log.WithError(err).Fatalf("Failed to parse %s: %s",
			option.MonitorAggregationName, err)
	}
	option.Config.Opts.SetValidated(option.MonitorAggregation, monitorAggregationLevel)

	policy.SetPolicyEnabled(option.Config.EnablePolicy)

	if err := identity.AddUserDefinedNumericIdentitySet(option.Config.FixedIdentityMapping); err != nil {
		log.Fatalf("Invalid fixed identities provided: %s", err)
	}

	if !option.Config.EnableIPv4 && !option.Config.EnableIPv6 {
		log.Fatal("Either IPv4 or IPv6 addressing must be enabled")
	}
	if err := labelsfilter.ParseLabelPrefixCfg(option.Config.Labels, option.Config.LabelPrefixFile); err != nil {
		log.WithError(err).Fatal("Unable to parse Label prefix configuration")
	}

	_, r, err := net.ParseCIDR(option.Config.NAT46Range)
	if err != nil {
		log.WithError(err).WithField(logfields.V6Prefix, option.Config.NAT46Range).Fatal("Invalid NAT46 prefix")
	}

	option.Config.NAT46Prefix = r

	switch option.Config.DatapathMode {
	case datapathOption.DatapathModeVeth:
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
		}
	case datapathOption.DatapathModeIpvlan:
		if option.Config.Tunnel != "" && option.Config.Tunnel != option.TunnelDisabled {
			log.WithField(logfields.Tunnel, option.Config.Tunnel).
				Fatal("tunnel cannot be set in the 'ipvlan' datapath mode")
		}
		if len(option.Config.Devices) != 0 {
			log.WithField(logfields.Devices, option.Config.Devices).
				Fatal("device cannot be set in the 'ipvlan' datapath mode")
		}
		if option.Config.EnableIPSec {
			log.Fatal("Currently ipsec cannot be used in the 'ipvlan' datapath mode.")
		}

		option.Config.Tunnel = option.TunnelDisabled
		// We disallow earlier command line combination of --device with
		// --datapath-mode ipvlan. But given all the remaining logic is
		// shared with option.Config.Devices, override it here internally
		// with the specified ipvlan master device. Reason to have a
		// separate, more specific command line parameter here and in
		// the swagger API is that in future we might deprecate --device
		// parameter with e.g. some auto-detection mechanism, thus for
		// ipvlan it is desired to have a separate one, see PR #6608.
		iface := viper.GetString(option.IpvlanMasterDevice)
		if iface == "undefined" {
			log.WithField(logfields.IpvlanMasterDevice, option.Config.Devices[0]).
				Fatal("ipvlan master device must be specified in the 'ipvlan' datapath mode")
		}
		option.Config.Devices = []string{iface}
		link, err := netlink.LinkByName(option.Config.Devices[0])
		if err != nil {
			log.WithError(err).WithField(logfields.IpvlanMasterDevice, option.Config.Devices[0]).
				Fatal("Cannot find device interface")
		}
		option.Config.Ipvlan.MasterDeviceIndex = link.Attrs().Index
		option.Config.Ipvlan.OperationMode = connector.OperationModeL3
		if option.Config.InstallIptRules {
			option.Config.Ipvlan.OperationMode = connector.OperationModeL3S
		}
	default:
		log.WithField(logfields.DatapathMode, option.Config.DatapathMode).Fatal("Invalid datapath mode")
	}

	if option.Config.EnableL7Proxy && !option.Config.InstallIptRules {
		log.Fatal("L7 proxy requires iptables rules (--install-iptables-rules=\"true\")")
	}

	if option.Config.EnableIPSec && option.Config.Tunnel == option.TunnelDisabled && option.Config.EncryptInterface == "" {
		link, err := linuxdatapath.NodeDeviceNameWithDefaultRoute()
		if err != nil {
			log.WithError(err).Fatal("Ipsec default interface lookup failed, consider \"encrypt-interface\" to manually configure interface.")
		}
		option.Config.EncryptInterface = link
	}

	checkHostFirewallWithEgressLB()
	initClockSourceOption()
	initSockmapOption()

	if option.Config.EnableHostFirewall && len(option.Config.Devices) == 0 {
		device, err := linuxdatapath.NodeDeviceNameWithDefaultRoute()
		if err != nil {
			msg := "Host firewall's external facing device could not be determined. Use --%s to specify."
			log.WithError(err).Fatalf(msg, option.Device)
		}
		log.WithField(logfields.Interface, device).
			Info("Using auto-derived device for host firewall")
		option.Config.Devices = []string{device}
	}

	// If there is one device specified, use it to derive better default
	// allocation prefixes
	node.InitDefaultPrefix(option.Config.Devices)

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

	k8s.SidecarIstioProxyImageRegexp, err = regexp.Compile(option.Config.SidecarIstioProxyImage)
	if err != nil {
		log.WithError(err).Fatal("Invalid sidecar-istio-proxy-image regular expression")
		return
	}

	if option.Config.EnableIPv4FragmentsTracking {
		if !option.Config.EnableIPv4 {
			option.Config.EnableIPv4FragmentsTracking = false
		} else {
			supportedMapTypes := probes.NewProbeManager().GetMapTypes()
			if !supportedMapTypes.HaveLruHashMapType {
				option.Config.EnableIPv4FragmentsTracking = false
				log.Info("Disabled support for IPv4 fragments due to missing kernel support for BPF LRU maps")
			}
		}
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
			Context:     d.ctx,
		},
	)

	// If K8s is enabled we can do the service translation automagically by
	// looking at services from k8s and retrieve the service IP from that.
	// This makes cilium to not depend on kube dns to interact with etcd
	_, isETCDOperator := kvstore.IsEtcdOperator(option.Config.KVStore, option.Config.KVStoreOpt, option.Config.K8sNamespace)
	if k8s.IsEnabled() && isETCDOperator {
		// Wait services and endpoints cache are synced with k8s before setting
		// up etcd so we can perform the name resolution for etcd-operator
		// to the service IP as well perform the service -> backend IPs for
		// that service IP.
		d.k8sWatcher.WaitForCacheSync(watchers.K8sAPIGroupServiceV1Core, watchers.K8sAPIGroupEndpointV1Core)
		log := log.WithField(logfields.LogSubsys, "etcd")
		goopts.DialOption = []grpc.DialOption{
			grpc.WithDialer(k8s.CreateCustomDialer(&d.k8sWatcher.K8sSvcCache, log)),
		}
	}

	if err := kvstore.Setup(context.TODO(), option.Config.KVStore, option.Config.KVStoreOpt, goopts); err != nil {
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

	if k8s.IsEnabled() {
		bootstrapStats.k8sInit.Start()
		if err := k8s.Init(option.Config); err != nil {
			log.WithError(err).Fatal("Unable to initialize Kubernetes subsystem")
		}
		bootstrapStats.k8sInit.End(true)
	}

	d, restoredEndpoints, err := NewDaemon(server.ServerCtx, linuxdatapath.NewDatapath(datapathConfig, iptablesManager))
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
		cleanup.DeferTerminationCleanupFunction(cleaner.cleanUPWg, cleaner.cleanUPSig, func() {
			d.compilationMutex.Lock()
			d.Datapath().Loader().DeleteDatapath(context.Background(), option.FlannelMasterDevice, "egress")
			d.compilationMutex.Unlock()
		})
	}

	bootstrapStats.enableConntrack.Start()
	log.Info("Starting connection tracking garbage collector")
	gc.Enable(option.Config.EnableIPv4, option.Config.EnableIPv6,
		restoredEndpoints.restored, d.endpointManager)
	bootstrapStats.enableConntrack.End(true)

	bootstrapStats.k8sInit.Start()

	if option.Config.KVStore == "" {
		log.Info("Skipping kvstore configuration")
	} else {
		d.initKVStore()
	}

	// Wait only for certain caches, but not all!
	// (Check Daemon.initK8sSubsystem() for more info)
	<-d.k8sCachesSynced
	bootstrapStats.k8sInit.End(true)
	restoreComplete := d.initRestore(restoredEndpoints)

	if !d.endpointManager.HostEndpointExists() {
		log.Info("Creating host endpoint")
		if err := d.endpointManager.AddHostEndpoint(d.ctx, d, d.l7Proxy, d.identityAllocator,
			"Create host endpoint", nodeTypes.GetName()); err != nil {
			log.WithError(err).Fatal("Unable to create host endpoint")
		}
	}

	if option.Config.IsFlannelMasterDeviceSet() {
		if option.Config.EnableEndpointHealthChecking {
			log.Warn("Running Cilium in flannel mode doesn't support endpoint connectivity health checking. Disabling endpoint connectivity health check.")
			option.Config.EnableEndpointHealthChecking = false
		}

		err := node.SetInternalIPv4From(option.Config.FlannelMasterDevice)
		if err != nil {
			log.WithError(err).WithField("device", option.Config.FlannelMasterDevice).Fatal("Unable to set internal IPv4")
		}
	}

	if option.Config.EnableIPMasqAgent {
		ipmasqAgent, err := ipmasq.NewIPMasqAgent(option.Config.IPMasqAgentConfigPath)
		if err != nil {
			log.WithError(err).Fatal("Failed to create ip-masq-agent")
		}
		ipmasqAgent.Start()
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

	bootstrapStats.healthCheck.Start()
	if option.Config.EnableHealthChecking {
		d.initHealth()
	}
	bootstrapStats.healthCheck.End(true)

	d.startStatusCollector()

	metricsErrs := initMetrics()

	d.startAgentHealthHTTPService(fmt.Sprintf("localhost:%d", option.Config.AgentHealthPort))

	bootstrapStats.initAPI.Start()
	srv := server.NewServer(d.instantiateAPI())
	srv.EnabledListeners = []string{"unix"}
	srv.SocketPath = option.Config.SocketPath
	srv.ReadTimeout = apiTimeout
	srv.WriteTimeout = apiTimeout
	defer srv.Shutdown()

	srv.ConfigureAPI()
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
		errs <- srv.Serve()
	}()

	if k8s.IsEnabled() {
		bootstrapStats.k8sInit.Start()
		k8s.Client().MarkNodeReady(nodeTypes.GetName())
		bootstrapStats.k8sInit.End(true)
	}

	bootstrapStats.overall.End(true)
	bootstrapStats.updateMetrics()
	d.launchHubble()

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
	restAPI := restapi.NewCiliumAPI(swaggerSpec)

	restAPI.Logger = log.Infof

	// /healthz/
	restAPI.DaemonGetHealthzHandler = NewGetHealthzHandler(d)

	// /cluster/nodes
	restAPI.DaemonGetClusterNodesHandler = NewGetClusterNodesHandler(d)

	// /config/
	restAPI.DaemonGetConfigHandler = NewGetConfigHandler(d)
	restAPI.DaemonPatchConfigHandler = NewPatchConfigHandler(d)

	// /endpoint/
	restAPI.EndpointGetEndpointHandler = NewGetEndpointHandler(d)

	// /endpoint/{id}
	restAPI.EndpointGetEndpointIDHandler = NewGetEndpointIDHandler(d)
	restAPI.EndpointPutEndpointIDHandler = NewPutEndpointIDHandler(d)
	restAPI.EndpointPatchEndpointIDHandler = NewPatchEndpointIDHandler(d)
	restAPI.EndpointDeleteEndpointIDHandler = NewDeleteEndpointIDHandler(d)

	// /endpoint/{id}config/
	restAPI.EndpointGetEndpointIDConfigHandler = NewGetEndpointIDConfigHandler(d)
	restAPI.EndpointPatchEndpointIDConfigHandler = NewPatchEndpointIDConfigHandler(d)

	// /endpoint/{id}/labels/
	restAPI.EndpointGetEndpointIDLabelsHandler = NewGetEndpointIDLabelsHandler(d)
	restAPI.EndpointPatchEndpointIDLabelsHandler = NewPatchEndpointIDLabelsHandler(d)

	// /endpoint/{id}/log/
	restAPI.EndpointGetEndpointIDLogHandler = NewGetEndpointIDLogHandler(d)

	// /endpoint/{id}/healthz
	restAPI.EndpointGetEndpointIDHealthzHandler = NewGetEndpointIDHealthzHandler(d)

	// /identity/
	restAPI.PolicyGetIdentityHandler = newGetIdentityHandler(d)
	restAPI.PolicyGetIdentityIDHandler = newGetIdentityIDHandler(d.identityAllocator)

	// /identity/endpoints
	restAPI.PolicyGetIdentityEndpointsHandler = newGetIdentityEndpointsIDHandler(d)

	// /policy/
	restAPI.PolicyGetPolicyHandler = newGetPolicyHandler(d.policy)
	restAPI.PolicyPutPolicyHandler = newPutPolicyHandler(d)
	restAPI.PolicyDeletePolicyHandler = newDeletePolicyHandler(d)
	restAPI.PolicyGetPolicySelectorsHandler = newGetPolicyCacheHandler(d)

	// /policy/resolve/
	restAPI.PolicyGetPolicyResolveHandler = NewGetPolicyResolveHandler(d)

	// /service/{id}/
	restAPI.ServiceGetServiceIDHandler = NewGetServiceIDHandler(d.svc)
	restAPI.ServiceDeleteServiceIDHandler = NewDeleteServiceIDHandler(d.svc)
	restAPI.ServicePutServiceIDHandler = NewPutServiceIDHandler(d.svc)

	// /service/
	restAPI.ServiceGetServiceHandler = NewGetServiceHandler(d.svc)

	// /prefilter/
	restAPI.PrefilterGetPrefilterHandler = NewGetPrefilterHandler(d)
	restAPI.PrefilterDeletePrefilterHandler = NewDeletePrefilterHandler(d)
	restAPI.PrefilterPatchPrefilterHandler = NewPatchPrefilterHandler(d)

	// /ipam/{ip}/
	restAPI.IpamPostIpamHandler = NewPostIPAMHandler(d)
	restAPI.IpamPostIpamIPHandler = NewPostIPAMIPHandler(d)
	restAPI.IpamDeleteIpamIPHandler = NewDeleteIPAMIPHandler(d)

	// /debuginfo
	restAPI.DaemonGetDebuginfoHandler = NewGetDebugInfoHandler(d)

	// /map
	restAPI.DaemonGetMapHandler = NewGetMapHandler(d)
	restAPI.DaemonGetMapNameHandler = NewGetMapNameHandler(d)

	// metrics
	restAPI.MetricsGetMetricsHandler = NewGetMetricsHandler(d)

	// /fqdn/cache
	restAPI.PolicyGetFqdnCacheHandler = NewGetFqdnCacheHandler(d)
	restAPI.PolicyDeleteFqdnCacheHandler = NewDeleteFqdnCacheHandler(d)
	restAPI.PolicyGetFqdnCacheIDHandler = NewGetFqdnCacheIDHandler(d)
	restAPI.PolicyGetFqdnNamesHandler = NewGetFqdnNamesHandler(d)

	// /ip/
	restAPI.PolicyGetIPHandler = NewGetIPHandler()

	return restAPI
}

func initSockmapOption() {
	if !option.Config.SockopsEnable {
		return
	}
	if probes.NewProbeManager().GetMapTypes().HaveSockhashMapType {
		k := probes.NewProbeManager().GetHelpers("sock_ops")
		h := probes.NewProbeManager().GetHelpers("sk_msg")
		if h != nil && k != nil {
			return
		}
	}
	log.Warn("BPF Sock ops not supported by kernel. Disabling '--sockops-enable' feature.")
	option.Config.SockopsEnable = false
}

func initClockSourceOption() {
	option.Config.ClockSource = option.ClockSourceKtime
	option.Config.KernelHz = 1 // Known invalid non-zero to avoid div by zero.
	if !option.Config.DryMode {
		hz, err := probes.NewProbeManager().SystemKernelHz()
		if err != nil {
			log.WithError(err).Infof("Auto-disabling %q feature since KERNEL_HZ cannot be determined",
				option.EnableBPFClockProbe)
			option.Config.EnableBPFClockProbe = false
		} else {
			option.Config.KernelHz = hz
		}

		if option.Config.EnableBPFClockProbe {
			if h := probes.NewProbeManager().GetHelpers("xdp"); h != nil {
				if _, ok := h["bpf_jiffies64"]; ok {
					t, err := bpf.GetJtime()
					if err == nil && t > 0 {
						option.Config.ClockSource = option.ClockSourceJiffies
					}
				}
			}
		}
	}
}

func checkHostFirewallWithEgressLB() {
	// Egress LB is enabled in datapath under condition:
	// ENABLE_SERVICES && (!ENABLE_HOST_SERVICES_FULL || \
	//                    (ENABLE_EXTERNAL_IP && !BPF_HAVE_NETNS_COOKIE))
	// We can't enable both egress LB and host firewall on kernels <4.14 due to
	// the verifier complexity limit, at 96k instructions.
	var netnsCookieSupport bool
	pm := probes.NewProbeManager()
	h1, h2 := pm.GetHelpers("cgroup_sock_addr"), pm.GetHelpers("cgroup_sock")
	if _, ok := h1["bpf_get_netns_cookie"]; ok {
		if _, ok := h2["bpf_get_netns_cookie"]; ok {
			netnsCookieSupport = true
		}
	}
	egressLBEnabled := !option.Config.DisableK8sServices &&
		(!option.Config.EnableHostServicesTCP || !option.Config.EnableHostServicesUDP ||
			(option.Config.EnableExternalIPs && !netnsCookieSupport))
	if option.Config.EnableHostFirewall && egressLBEnabled {
		log.Warn("Enabling both BPF-based east-west load balancing and the host firewall isn't supported yet. Disabling east-west load balancing.")
		option.Config.DisableK8sServices = true
		option.Config.KubeProxyReplacement = option.KubeProxyReplacementDisabled
	}
}

func initKubeProxyReplacementOptions() {
	if option.Config.KubeProxyReplacement != option.KubeProxyReplacementStrict &&
		option.Config.KubeProxyReplacement != option.KubeProxyReplacementPartial &&
		option.Config.KubeProxyReplacement != option.KubeProxyReplacementProbe &&
		option.Config.KubeProxyReplacement != option.KubeProxyReplacementDisabled {
		log.Fatalf("Invalid value for --%s: %s", option.KubeProxyReplacement, option.Config.KubeProxyReplacement)
	}

	probesManager := probes.NewProbeManager()

	if option.Config.DisableK8sServices {
		if option.Config.KubeProxyReplacement != option.KubeProxyReplacementDisabled {
			log.Warnf("Service handling disabled. Auto-disabling --%s from \"%s\" to \"%s\"",
				option.KubeProxyReplacement, option.Config.KubeProxyReplacement,
				option.KubeProxyReplacementDisabled)
			option.Config.KubeProxyReplacement = option.KubeProxyReplacementDisabled
		}
	}

	if option.Config.KubeProxyReplacement == option.KubeProxyReplacementDisabled {
		log.Infof("Auto-disabling %q, %q, %q, %q features", option.EnableNodePort,
			option.EnableExternalIPs, option.EnableHostReachableServices,
			option.EnableHostPort)

		option.Config.EnableHostPort = false
		option.Config.EnableNodePort = false
		option.Config.EnableExternalIPs = false
		option.Config.EnableHostReachableServices = false
		option.Config.EnableHostServicesTCP = false
		option.Config.EnableHostServicesUDP = false
		option.Config.EnableSessionAffinity = false

		return
	}

	// strict denotes to panic if any to-be enabled feature cannot be enabled
	strict := option.Config.KubeProxyReplacement != option.KubeProxyReplacementProbe

	if option.Config.KubeProxyReplacement == option.KubeProxyReplacementProbe ||
		option.Config.KubeProxyReplacement == option.KubeProxyReplacementStrict {

		log.Infof("Auto-enabling %q, %q, %q, %q features", option.EnableNodePort,
			option.EnableExternalIPs, option.EnableHostReachableServices,
			option.EnableHostPort)

		option.Config.EnableHostPort = true
		option.Config.EnableNodePort = true
		option.Config.EnableExternalIPs = true
		option.Config.EnableHostReachableServices = true
		option.Config.EnableHostServicesTCP = true
		option.Config.EnableHostServicesUDP = true
		option.Config.EnableSessionAffinity = true
		option.Config.DisableK8sServices = false
	}

	if option.Config.EnableNodePort {
		if option.Config.EnableIPSec {
			msg := "IPSec cannot be used with NodePort BPF."
			if strict {
				log.Fatal(msg)
			} else {
				option.Config.EnableHostPort = false
				option.Config.EnableNodePort = false
				option.Config.EnableExternalIPs = false
				log.Warn(msg + " Disabling the feature.")
			}
		}

		if option.Config.NodePortMode != option.NodePortModeSNAT &&
			option.Config.NodePortMode != option.NodePortModeDSR &&
			option.Config.NodePortMode != option.NodePortModeHybrid {
			log.Fatalf("Invalid value for --%s: %s", option.NodePortMode, option.Config.NodePortMode)
		}

		if option.Config.NodePortAcceleration != option.NodePortAccelerationNone &&
			option.Config.NodePortAcceleration != option.NodePortAccelerationGeneric &&
			option.Config.NodePortAcceleration != option.NodePortAccelerationNative {
			log.Fatalf("Invalid value for --%s: %s", option.NodePortAcceleration, option.Config.NodePortAcceleration)
		}

		if !option.Config.NodePortBindProtection {
			log.Warning("NodePort BPF configured without bind(2) protection against service ports")
		}
	}

	if option.Config.EnableNodePort {
		found := false
		if h := probesManager.GetHelpers("sched_act"); h != nil {
			if _, ok := h["bpf_fib_lookup"]; ok {
				found = true
			}
		}
		if !found {
			msg := "BPF NodePort services needs kernel 4.17.0 or newer."
			if strict {
				log.Fatal(msg)
			} else {
				log.Warn(msg + " Disabling the feature.")
				option.Config.EnableHostPort = false
				option.Config.EnableNodePort = false
				option.Config.EnableExternalIPs = false
			}
		}

		if err := checkNodePortAndEphemeralPortRanges(); err != nil {
			if strict {
				log.Fatal(err)
			} else {
				log.Warn(fmt.Sprintf("%s Disabling the feature.", err))
				option.Config.EnableHostPort = false
				option.Config.EnableNodePort = false
				option.Config.EnableExternalIPs = false
			}
		}
	}

	if option.Config.EnableNodePort && len(option.Config.Devices) == 0 {
		device, err := linuxdatapath.NodeDeviceNameWithDefaultRoute()
		if err != nil {
			msg := "BPF NodePort's external facing device could not be determined. Use --device to specify."
			if strict {
				log.WithError(err).Fatal(msg)
			} else {
				log.WithError(err).Warn(msg + " Disabling BPF NodePort feature.")
				option.Config.EnableHostPort = false
				option.Config.EnableNodePort = false
				option.Config.EnableExternalIPs = false
			}
		} else {
			log.WithField(logfields.Interface, device).
				Info("Using auto-derived device for BPF node port")
			option.Config.Devices = []string{device}
		}
	}

	if option.Config.EnableNodePort &&
		option.Config.NodePortAcceleration != option.NodePortAccelerationNone {
		if option.Config.Tunnel != option.TunnelDisabled {
			log.Fatalf("Cannot use NodePort acceleration with tunneling. Either run cilium-agent with --%s=%s or --%s=%s",
				option.NodePortAcceleration, option.NodePortAccelerationNone, option.TunnelName, option.TunnelDisabled)
		}

		if option.Config.XDPDevice != "undefined" &&
			(len(option.Config.Devices) == 0 ||
				option.Config.XDPDevice != option.Config.Devices[0]) {
			log.Fatalf("Cannot set NodePort acceleration device: mismatch between Prefilter device %s and NodePort device %s",
				option.Config.XDPDevice, option.Config.Devices[0])
		}
		// TODO(brb) support multi-dev for XDP
		option.Config.XDPDevice = option.Config.Devices[0]
		if err := loader.SetXDPMode(option.Config.NodePortAcceleration); err != nil {
			log.WithError(err).Fatal("Cannot set NodePort acceleration")
		}
	}
	if option.Config.EnableNodePort {
		for _, iface := range option.Config.Devices {
			link, err := netlink.LinkByName(iface)
			if err != nil {
				log.WithError(err).Fatalf("Cannot retrieve %s link", iface)
			}
			if strings.ContainsAny(iface, "=;") {
				// Because we pass IPV{4,6}_NODEPORT addresses to bpf/init.sh
				// in a form "$IFACE_NAME1=$IPV{4,6}_ADDR1;$IFACE_NAME2=...",
				// we need to restrict the iface names. Otherwise, bpf/init.sh
				// won't properly parse the mappings.
				log.Fatalf("%s link name contains '=' or ';' character which is not allowed",
					iface)
			}
			if idx := link.Attrs().Index; idx > math.MaxUint16 {
				log.Fatalf("%s link ifindex %d exceeds max(uint16)", iface, idx)
			}
		}

		if option.Config.EnableIPv4 &&
			option.Config.Tunnel == option.TunnelDisabled &&
			option.Config.NodePortMode != option.NodePortModeSNAT &&
			len(option.Config.Devices) > 1 {

			// In the case of the multi-dev NodePort DSR, if a request from an
			// external client was sent to a device which is not used for direct
			// routing, such request might be dropped by the destination node
			// if the destination node's direct routing device's rp_filter = 1
			// and the client IP is reachable via other device than the direct
			// routing one.

			iface := option.Config.Devices[0] // direct routing interface
			if val, err := sysctl.Read(fmt.Sprintf("net.ipv4.conf.%s.rp_filter", iface)); err != nil {
				log.Warnf("Unable to read net.ipv4.conf.%s.rp_filter: %s. Ignoring the check",
					iface, err)
			} else {
				if val == "1" {
					log.Warnf(`DSR might not work for requests sent to other than %s device. `+
						`Run 'sysctl -w net.ipv4.conf.%s.rp_filter=2' (or set to '0') on each node to fix`,
						iface, iface)
				}
			}
		}
	}

	if option.Config.EnableHostReachableServices {
		// Try to auto-load IPv6 module if it hasn't been done yet as there can
		// be v4-in-v6 connections even if the agent has v6 support disabled.
		probe.HaveIPv6Support()

		option.Config.EnableHostServicesPeer = true
		if option.Config.EnableIPv4 && bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_INET4_GETPEERNAME) != nil ||
			option.Config.EnableIPv6 && bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_INET6_GETPEERNAME) != nil {
			option.Config.EnableHostServicesPeer = false
		}

		if option.Config.EnableHostServicesTCP &&
			(option.Config.EnableIPv4 && bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_INET4_CONNECT) != nil ||
				option.Config.EnableIPv6 && bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_INET6_CONNECT) != nil) {
			msg := "BPF host reachable services for TCP needs kernel 4.17.0 or newer."
			if strict {
				log.Fatal(msg)
			} else {
				option.Config.EnableHostServicesTCP = false
				log.Warn(msg + " Disabling the feature.")
			}
		}
		if option.Config.EnableHostServicesUDP &&
			(option.Config.EnableIPv4 && bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_UDP4_RECVMSG) != nil ||
				option.Config.EnableIPv6 && bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_UDP6_RECVMSG) != nil) {
			msg := "BPF host reachable services for UDP needs kernel 4.19.57, 5.1.16, 5.2.0 or newer. If you run an older kernel and only need TCP, then specify: --host-reachable-services-protos=tcp"
			if strict {
				log.Fatal(msg)
			} else {
				option.Config.EnableHostServicesUDP = false
				log.Warn(msg + " Disabling the feature.")
			}
		}
		if !option.Config.EnableHostServicesTCP && !option.Config.EnableHostServicesUDP {
			option.Config.EnableHostReachableServices = false
		}
	} else {
		option.Config.EnableHostServicesTCP = false
		option.Config.EnableHostServicesUDP = false
	}

	if !option.Config.EnableNodePort {
		option.Config.EnableHostPort = false
		option.Config.EnableExternalIPs = false
	} else {
		if option.Config.Tunnel != option.TunnelDisabled &&
			option.Config.NodePortMode != option.NodePortModeSNAT {

			log.Warnf("Disabling NodePort's %q mode feature due to tunneling mode being enabled",
				option.Config.NodePortMode)
			option.Config.NodePortMode = option.NodePortModeSNAT
		}
	}

	if option.Config.EnableSessionAffinity {
		if !probesManager.GetMapTypes().HaveLruHashMapType {
			msg := "SessionAffinity feature requires BPF LRU maps"
			if strict {
				log.Fatal(msg)
			} else {
				log.Warnf("%s. Disabling the feature.", msg)
				option.Config.EnableSessionAffinity = false
			}

		}
	}

	if option.Config.EnableSessionAffinity && option.Config.EnableHostReachableServices {
		found1, found2 := false, false
		if h := probesManager.GetHelpers("cgroup_sock"); h != nil {
			_, found1 = h["bpf_get_netns_cookie"]
		}
		if h := probesManager.GetHelpers("cgroup_sock_addr"); h != nil {
			_, found2 = h["bpf_get_netns_cookie"]
		}
		if !(found1 && found2) {
			log.Warn("Session affinity for host reachable services needs kernel 5.7.0 or newer " +
				"to work properly when accessed from inside cluster: the same service endpoint " +
				"will be selected from all network namespaces on the host.")
		}
	}
}

// checkNodePortAndEphemeralPortRanges checks whether the ephemeral port range
// does not clash with the nodeport range to prevent the BPF nodeport from
// hijacking an existing connection on the local host which source port is
// the same as a nodeport service.
//
// If it clashes, check whether the nodeport range is listed in ip_local_reserved_ports.
// If it isn't and EnableAutoProtectNodePortRange == false, then return an error
// making cilium-agent to stop.
// Otherwise, if EnableAutoProtectNodePortRange == true, then append the nodeport
// range to ip_local_reserved_ports.
func checkNodePortAndEphemeralPortRanges() error {
	ephemeralPortRangeStr, err := sysctl.Read("net.ipv4.ip_local_port_range")
	if err != nil {
		return fmt.Errorf("Unable to read net.ipv4.ip_local_port_range")
	}
	ephemeralPortRange := strings.Split(ephemeralPortRangeStr, "\t")
	if len(ephemeralPortRange) != 2 {
		return fmt.Errorf("Invalid ephemeral port range: %s", ephemeralPortRangeStr)
	}
	ephemeralPortMin, err := strconv.Atoi(ephemeralPortRange[0])
	if err != nil {
		return fmt.Errorf("Unable to parse min port value %s for ephemeral range", ephemeralPortRange[0])
	}
	ephemeralPortMax, err := strconv.Atoi(ephemeralPortRange[1])
	if err != nil {
		return fmt.Errorf("Unable to parse max port value %s for ephemeral range", ephemeralPortRange[1])
	}

	if option.Config.NodePortMax < ephemeralPortMin {
		// ephemeral port range does not clash with nodeport range
		return nil
	}

	nodePortRangeStr := fmt.Sprintf("%d-%d", option.Config.NodePortMin,
		option.Config.NodePortMax)

	if option.Config.NodePortMin > ephemeralPortMax {
		return fmt.Errorf("NodePort port range (%s) is not allowed to be after ephemeral port range (%s)",
			nodePortRangeStr, ephemeralPortRangeStr)
	}

	reservedPortsStr, err := sysctl.Read("net.ipv4.ip_local_reserved_ports")
	if err != nil {
		return fmt.Errorf("Unable to read net.ipv4.ip_local_reserved_ports")
	}
	for _, portRange := range strings.Split(reservedPortsStr, ",") {
		if portRange == "" {
			break
		}
		ports := strings.Split(portRange, "-")
		if len(ports) == 0 {
			return fmt.Errorf("Invalid reserved ports range")
		}
		from, err := strconv.Atoi(ports[0])
		if err != nil {
			return fmt.Errorf("Unable to parse reserved port %q", ports[0])
		}
		to := from
		if len(ports) == 2 {
			if to, err = strconv.Atoi(ports[1]); err != nil {
				return fmt.Errorf("Unable to parse reserved port %q", ports[1])
			}
		}

		if from <= option.Config.NodePortMin && to >= option.Config.NodePortMax {
			// nodeport range is protected by reserved port range
			return nil
		}

		if from > option.Config.NodePortMax {
			break
		}
	}

	if !option.Config.EnableAutoProtectNodePortRange {
		msg := `NodePort port range (%s) must not clash with ephemeral port range (%s). ` +
			`Adjust ephemeral range port with "sysctl -w net.ipv4.ip_local_port_range='MIN MAX'", or ` +
			`protect the NodePort range by appending it to "net.ipv4.ip_local_reserved_ports", or ` +
			`set --%s=true to auto-append the range to "net.ipv4.ip_local_reserved_ports"`
		return fmt.Errorf(msg, nodePortRangeStr, ephemeralPortRangeStr,
			option.EnableAutoProtectNodePortRange)
	}

	if reservedPortsStr != "" {
		reservedPortsStr += ","
	}
	reservedPortsStr += fmt.Sprintf("%d-%d", option.Config.NodePortMin, option.Config.NodePortMax)
	if err := sysctl.Write("net.ipv4.ip_local_reserved_ports", reservedPortsStr); err != nil {
		return fmt.Errorf("Unable to addend nodeport range (%s) to net.ipv4.ip_local_reserved_ports: %s",
			nodePortRangeStr, err)
	}

	return nil
}
