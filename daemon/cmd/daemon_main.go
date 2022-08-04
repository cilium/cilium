// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-openapi/loads"
	gops "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/fx"
	"google.golang.org/grpc"

	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/api/v1/server/restapi"
	"github.com/cilium/cilium/pkg/aws/eni"
	bgpv1 "github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/gobgp"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/link"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/datapath/maps"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/hubble/exporter/exporteroption"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/identity"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipmasq"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/loadinfo"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/ctmap/gc"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/neighborsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/cilium/cilium/pkg/version"
	wireguard "github.com/cilium/cilium/pkg/wireguard/agent"
	wireguardTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

const (
	// list of supported verbose debug groups
	argDebugVerboseFlow     = "flow"
	argDebugVerboseKvstore  = "kvstore"
	argDebugVerboseEnvoy    = "envoy"
	argDebugVerboseDatapath = "datapath"
	argDebugVerbosePolicy   = "policy"

	apiTimeout   = 60 * time.Second
	daemonSubsys = "daemon"

	// fatalSleep is the duration Cilium should sleep before existing in case
	// of a log.Fatal is issued or a CLI flag is specified but does not exist.
	fatalSleep = 2 * time.Second
)

var (
	Vp      *viper.Viper              = viper.New()
	regOpts *option.RegisteredOptions = option.NewRegisteredOptions(Vp)

	log = logging.DefaultLogger.WithField(logfields.LogSubsys, daemonSubsys)

	bootstrapTimestamp = time.Now()

	// RootCmd represents the base command when called without any subcommands
	RootCmd = &cobra.Command{
		Use:   "cilium-agent",
		Short: "Run the cilium agent",
		Run: func(cmd *cobra.Command, args []string) {
			cmdRefDir := Vp.GetString(option.CMDRef)
			if cmdRefDir != "" {
				genMarkdown(cmd, cmdRefDir)
				os.Exit(0)
			}

			// Open socket for using gops to get stacktraces of the agent.
			addr := fmt.Sprintf("127.0.0.1:%d", Vp.GetInt(option.GopsPort))
			addrField := logrus.Fields{"address": addr}
			if err := gops.Listen(gops.Options{
				Addr:                   addr,
				ReuseSocketAddrAndPort: true,
			}); err != nil {
				log.WithError(err).WithFields(addrField).Fatal("Cannot start gops server")
			}
			log.WithFields(addrField).Info("Started gops server")

			bootstrapStats.earlyInit.Start()
			initEnv(cmd)
			bootstrapStats.earlyInit.End(true)

			runApp()
		},
	}

	bootstrapStats = bootstrapStatistics{}
)

// Execute sets up gops, installs the cleanup signal handler and invokes
// the root command. This function only returns when an interrupt
// signal has been received. This is intended to be called by main.main().
func Execute() {
	bootstrapStats.overall.Start()

	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	setupSleepBeforeFatal()
	initializeFlags()
	registerBootstrapMetrics()
}

func setupSleepBeforeFatal() {
	RootCmd.SetFlagErrorFunc(func(_ *cobra.Command, e error) error {
		time.Sleep(fatalSleep)
		return e
	})
	logrus.RegisterExitHandler(func() {
		time.Sleep(fatalSleep)
	},
	)
}

func initializeFlags() {
	cobra.OnInitialize(option.InitConfig(RootCmd, "Cilium", "ciliumd", Vp))

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
	flags.Int(option.AgentHealthPort, defaults.AgentHealthPort, "TCP port for agent health status API")
	regOpts.BindEnv(option.AgentHealthPort)

	flags.Int(option.ClusterHealthPort, defaults.ClusterHealthPort, "TCP port for cluster-wide network connectivity health API")
	regOpts.BindEnv(option.ClusterHealthPort)

	flags.StringSlice(option.AgentLabels, []string{}, "Additional labels to identify this agent")
	regOpts.BindEnv(option.AgentLabels)

	flags.Bool(option.AllowICMPFragNeeded, defaults.AllowICMPFragNeeded, "Allow ICMP Fragmentation Needed type packets for purposes like TCP Path MTU.")
	regOpts.BindEnv(option.AllowICMPFragNeeded)

	flags.String(option.AllowLocalhost, option.AllowLocalhostAuto, "Policy when to allow local stack to reach local endpoints { auto | always | policy }")
	regOpts.BindEnv(option.AllowLocalhost)

	flags.Bool(option.AnnotateK8sNode, defaults.AnnotateK8sNode, "Annotate Kubernetes node")
	regOpts.BindEnv(option.AnnotateK8sNode)

	flags.Duration(option.ARPPingRefreshPeriod, defaults.ARPBaseReachableTime, "Period for remote node ARP entry refresh (set 0 to disable)")
	regOpts.BindEnv(option.ARPPingRefreshPeriod)

	flags.Bool(option.EnableL2NeighDiscovery, true, "Enables L2 neighbor discovery used by kube-proxy-replacement and IPsec")
	regOpts.BindEnv(option.EnableL2NeighDiscovery)

	flags.Bool(option.AutoCreateCiliumNodeResource, defaults.AutoCreateCiliumNodeResource, "Automatically create CiliumNode resource for own node on startup")
	regOpts.BindEnv(option.AutoCreateCiliumNodeResource)

	flags.String(option.BPFRoot, "", "Path to BPF filesystem")
	regOpts.BindEnv(option.BPFRoot)

	flags.Bool(option.EnableBPFClockProbe, false, "Enable BPF clock source probing for more efficient tick retrieval")
	regOpts.BindEnv(option.EnableBPFClockProbe)

	flags.String(option.CGroupRoot, "", "Path to Cgroup2 filesystem")
	regOpts.BindEnv(option.CGroupRoot)

	flags.Bool(option.SockopsEnableName, defaults.SockopsEnable, "Enable sockops when kernel supported")
	regOpts.BindEnv(option.SockopsEnableName)

	flags.Int(option.ClusterIDName, 0, "Unique identifier of the cluster")
	regOpts.BindEnv(option.ClusterIDName)

	flags.String(option.ClusterName, defaults.ClusterName, "Name of the cluster")
	regOpts.BindEnv(option.ClusterName)

	flags.String(option.ClusterMeshConfigName, "", "Path to the ClusterMesh configuration directory")
	regOpts.BindEnv(option.ClusterMeshConfigName)

	flags.StringSlice(option.CompilerFlags, []string{}, "Extra CFLAGS for BPF compilation")
	flags.MarkHidden(option.CompilerFlags)
	regOpts.BindEnv(option.CompilerFlags)

	flags.String(option.ConfigFile, "", `Configuration file (default "$HOME/ciliumd.yaml")`)
	regOpts.BindEnv(option.ConfigFile)

	flags.String(option.ConfigDir, "", `Configuration directory that contains a file for each option`)
	regOpts.BindEnv(option.ConfigDir)

	flags.Duration(option.ConntrackGCInterval, time.Duration(0), "Overwrite the connection-tracking garbage collection interval")
	regOpts.BindEnv(option.ConntrackGCInterval)

	flags.BoolP(option.DebugArg, "D", false, "Enable debugging mode")
	regOpts.BindEnv(option.DebugArg)

	flags.StringSlice(option.DebugVerbose, []string{}, "List of enabled verbose debug groups")
	regOpts.BindEnv(option.DebugVerbose)

	flags.StringSlice(option.Devices, []string{}, "List of devices facing cluster/external network (used for BPF NodePort, BPF masquerading and host firewall); supports '+' as wildcard in device name, e.g. 'eth+'")
	regOpts.BindEnv(option.Devices)

	flags.String(option.DirectRoutingDevice, "", "Device name used to connect nodes in direct routing mode (used by BPF NodePort, BPF host routing; if empty, automatically set to a device with k8s InternalIP/ExternalIP or with a default route)")
	regOpts.BindEnv(option.DirectRoutingDevice)

	flags.Bool(option.EnableRuntimeDeviceDetection, false, "Enable runtime device detection and datapath reconfiguration (experimental)")
	regOpts.BindEnv(option.EnableRuntimeDeviceDetection)

	flags.String(option.LBDevInheritIPAddr, "", fmt.Sprintf("Device name which IP addr is inherited by devices running LB BPF program (--%s)", option.Devices))
	regOpts.BindEnv(option.LBDevInheritIPAddr)

	flags.String(option.DatapathMode, defaults.DatapathMode, "Datapath mode name")
	regOpts.BindEnv(option.DatapathMode)

	flags.Bool(option.DisableConntrack, false, "Disable connection tracking")
	regOpts.BindEnv(option.DisableConntrack)
	flags.MarkDeprecated(option.DisableConntrack, "This option is no-op and it will be removed in v1.13")

	flags.Bool(option.EnableEndpointRoutes, defaults.EnableEndpointRoutes, "Use per endpoint routes instead of routing via cilium_host")
	regOpts.BindEnv(option.EnableEndpointRoutes)

	flags.Bool(option.EnableHealthChecking, defaults.EnableHealthChecking, "Enable connectivity health checking")
	regOpts.BindEnv(option.EnableHealthChecking)

	flags.Bool(option.EnableHealthCheckNodePort, defaults.EnableHealthCheckNodePort, "Enables a healthcheck nodePort server for NodePort services with 'healthCheckNodePort' being set")
	regOpts.BindEnv(option.EnableHealthCheckNodePort)

	flags.StringSlice(option.EndpointStatus, []string{},
		"Enable additional CiliumEndpoint status features ("+strings.Join(option.EndpointStatusValues(), ",")+")")
	regOpts.BindEnv(option.EndpointStatus)

	flags.Bool(option.EnableEndpointHealthChecking, defaults.EnableEndpointHealthChecking, "Enable connectivity health checking between virtual endpoints")
	regOpts.BindEnv(option.EnableEndpointHealthChecking)

	flags.Bool(option.EnableLocalNodeRoute, defaults.EnableLocalNodeRoute, "Enable installation of the route which points the allocation prefix of the local node")
	regOpts.BindEnv(option.EnableLocalNodeRoute)

	flags.Bool(option.EnableIPv4Name, defaults.EnableIPv4, "Enable IPv4 support")
	regOpts.BindEnv(option.EnableIPv4Name)

	flags.Bool(option.EnableIPv6Name, defaults.EnableIPv6, "Enable IPv6 support")
	regOpts.BindEnv(option.EnableIPv6Name)

	flags.Bool(option.EnableIPv6NDPName, defaults.EnableIPv6NDP, "Enable IPv6 NDP support")
	regOpts.BindEnv(option.EnableIPv6NDPName)

	flags.Bool(option.EnableSRv6, defaults.EnableSRv6, "Enable SRv6 support (beta)")
	flags.MarkHidden(option.EnableSRv6)
	regOpts.BindEnv(option.EnableSRv6)

	flags.String(option.IPv6MCastDevice, "", "Device that joins a Solicited-Node multicast group for IPv6")
	regOpts.BindEnv(option.IPv6MCastDevice)

	flags.Bool(option.EnableRemoteNodeIdentity, defaults.EnableRemoteNodeIdentity, "Enable use of remote node identity")
	regOpts.BindEnv(option.EnableRemoteNodeIdentity)

	flags.String(option.EncryptInterface, "", "Transparent encryption interface")
	regOpts.BindEnv(option.EncryptInterface)

	flags.Bool(option.EncryptNode, defaults.EncryptNode, "Enables encrypting traffic from non-Cilium pods and host networking")
	regOpts.BindEnv(option.EncryptNode)

	flags.StringSlice(option.IPv4PodSubnets, []string{}, "List of IPv4 pod subnets to preconfigure for encryption")
	regOpts.BindEnv(option.IPv4PodSubnets)

	flags.StringSlice(option.IPv6PodSubnets, []string{}, "List of IPv6 pod subnets to preconfigure for encryption")
	regOpts.BindEnv(option.IPv6PodSubnets)

	flags.String(option.EndpointInterfaceNamePrefix, "", "Prefix of interface name shared by all endpoints")
	regOpts.BindEnv(option.EndpointInterfaceNamePrefix)
	flags.MarkDeprecated(option.EndpointInterfaceNamePrefix, "This option no longer has any effect and will be removed in v1.13.")

	flags.StringSlice(option.ExcludeLocalAddress, []string{}, "Exclude CIDR from being recognized as local address")
	regOpts.BindEnv(option.ExcludeLocalAddress)

	flags.Bool(option.DisableCiliumEndpointCRDName, false, "Disable use of CiliumEndpoint CRD")
	regOpts.BindEnv(option.DisableCiliumEndpointCRDName)

	flags.String(option.EgressMasqueradeInterfaces, "", "Limit egress masquerading to interface selector")
	regOpts.BindEnv(option.EgressMasqueradeInterfaces)

	flags.Bool(option.BPFSocketLBHostnsOnly, false, "Skip socket LB for services when inside a pod namespace, in favor of service LB at the pod interface. Socket LB is still used when in the host namespace. Required by service mesh (e.g., Istio, Linkerd).")
	regOpts.BindEnv(option.BPFSocketLBHostnsOnly)

	flags.Bool(option.EnableSocketLB, false, "Enable socket-based LB for E/W traffic")
	regOpts.BindEnv(option.EnableSocketLB)

	flags.Bool(option.EnableHostReachableServices, false, "Enable reachability of services for host applications")
	regOpts.BindEnv(option.EnableHostReachableServices)
	flags.MarkDeprecated(option.EnableHostReachableServices,
		fmt.Sprintf("This option will be removed in v1.13. Use --%s instead", option.EnableSocketLB))

	flags.StringSlice(option.HostReachableServicesProtos, []string{option.HostServicesTCP, option.HostServicesUDP}, "Only enable reachability of services for host applications for specific protocols")
	regOpts.BindEnv(option.HostReachableServicesProtos)
	flags.MarkDeprecated(option.HostReachableServicesProtos, "This option will be removed in v1.13")

	flags.Bool(option.EnableAutoDirectRoutingName, defaults.EnableAutoDirectRouting, "Enable automatic L2 routing between nodes")
	regOpts.BindEnv(option.EnableAutoDirectRoutingName)

	flags.Bool(option.EnableBPFTProxy, defaults.EnableBPFTProxy, "Enable BPF-based proxy redirection, if support available")
	regOpts.BindEnv(option.EnableBPFTProxy)

	flags.Bool(option.EnableHostLegacyRouting, defaults.EnableHostLegacyRouting, "Enable the legacy host forwarding model which does not bypass upper stack in host namespace")
	regOpts.BindEnv(option.EnableHostLegacyRouting)

	flags.Bool(option.EnableXTSocketFallbackName, defaults.EnableXTSocketFallback, "Enable fallback for missing xt_socket module")
	regOpts.BindEnv(option.EnableXTSocketFallbackName)

	flags.String(option.EnablePolicy, option.DefaultEnforcement, "Enable policy enforcement")
	regOpts.BindEnv(option.EnablePolicy)

	flags.Bool(option.EnableExternalIPs, defaults.EnableExternalIPs, fmt.Sprintf("Enable k8s service externalIPs feature (requires enabling %s)", option.EnableNodePort))
	regOpts.BindEnv(option.EnableExternalIPs)

	flags.Bool(option.K8sEnableEndpointSlice, defaults.K8sEnableEndpointSlice, "Enables k8s EndpointSlice feature in Cilium if the k8s cluster supports it")
	regOpts.BindEnv(option.K8sEnableEndpointSlice)

	flags.Bool(option.K8sEnableAPIDiscovery, defaults.K8sEnableAPIDiscovery, "Enable discovery of Kubernetes API groups and resources with the discovery API")
	regOpts.BindEnv(option.K8sEnableAPIDiscovery)

	flags.Bool(option.EnableL7Proxy, defaults.EnableL7Proxy, "Enable L7 proxy for L7 policy enforcement")
	regOpts.BindEnv(option.EnableL7Proxy)

	flags.Bool(option.EnableTracing, false, "Enable tracing while determining policy (debugging)")
	regOpts.BindEnv(option.EnableTracing)

	flags.Bool(option.EnableUnreachableRoutes, false, "Add unreachable routes on pod deletion")
	regOpts.BindEnv(option.EnableUnreachableRoutes)

	flags.Bool(option.EnableWellKnownIdentities, defaults.EnableWellKnownIdentities, "Enable well-known identities for known Kubernetes components")
	regOpts.BindEnv(option.EnableWellKnownIdentities)

	flags.String(option.EnvoyLog, "", "Path to a separate Envoy log file, if any")
	regOpts.BindEnv(option.EnvoyLog)

	flags.Bool(option.EnableIPSecName, defaults.EnableIPSec, "Enable IPSec support")
	regOpts.BindEnv(option.EnableIPSecName)

	flags.String(option.IPSecKeyFileName, "", "Path to IPSec key file")
	regOpts.BindEnv(option.IPSecKeyFileName)

	flags.Bool(option.EnableWireguard, false, "Enable wireguard")
	regOpts.BindEnv(option.EnableWireguard)

	flags.Bool(option.EnableWireguardUserspaceFallback, false, "Enables the fallback to the wireguard userspace implementation")
	regOpts.BindEnv(option.EnableWireguardUserspaceFallback)

	flags.Bool(option.ForceLocalPolicyEvalAtSource, defaults.ForceLocalPolicyEvalAtSource, "Force policy evaluation of all local communication at the source endpoint")
	regOpts.BindEnv(option.ForceLocalPolicyEvalAtSource)

	flags.Bool(option.HTTPNormalizePath, true, "Use Envoy HTTP path normalization options, which currently includes RFC 3986 path normalization, Envoy merge slashes option, and unescaping and redirecting for paths that contain escaped slashes. These are necessary to keep path based access control functional, and should not interfere with normal operation. Set this to false only with caution.")
	regOpts.BindEnv(option.HTTPNormalizePath)

	flags.String(option.HTTP403Message, "", "Message returned in proxy L7 403 body")
	flags.MarkHidden(option.HTTP403Message)
	regOpts.BindEnv(option.HTTP403Message)

	flags.Uint(option.HTTPRequestTimeout, 60*60, "Time after which a forwarded HTTP request is considered failed unless completed (in seconds); Use 0 for unlimited")
	regOpts.BindEnv(option.HTTPRequestTimeout)

	flags.Uint(option.HTTPIdleTimeout, 0, "Time after which a non-gRPC HTTP stream is considered failed unless traffic in the stream has been processed (in seconds); defaults to 0 (unlimited)")
	regOpts.BindEnv(option.HTTPIdleTimeout)

	flags.Uint(option.HTTPMaxGRPCTimeout, 0, "Time after which a forwarded gRPC request is considered failed unless completed (in seconds). A \"grpc-timeout\" header may override this with a shorter value; defaults to 0 (unlimited)")
	regOpts.BindEnv(option.HTTPMaxGRPCTimeout)

	flags.Uint(option.HTTPRetryCount, 3, "Number of retries performed after a forwarded request attempt fails")
	regOpts.BindEnv(option.HTTPRetryCount)

	flags.Uint(option.HTTPRetryTimeout, 0, "Time after which a forwarded but uncompleted request is retried (connection failures are retried immediately); defaults to 0 (never)")
	regOpts.BindEnv(option.HTTPRetryTimeout)

	flags.Uint(option.ProxyConnectTimeout, 1, "Time after which a TCP connect attempt is considered failed unless completed (in seconds)")
	regOpts.BindEnv(option.ProxyConnectTimeout)

	flags.Uint(option.ProxyGID, 1337, "Group ID for proxy control plane sockets.")
	regOpts.BindEnv(option.ProxyGID)

	flags.Int(option.ProxyPrometheusPort, 0, "Port to serve Envoy metrics on. Default 0 (disabled).")
	regOpts.BindEnv(option.ProxyPrometheusPort)

	flags.Int(option.ProxyMaxRequestsPerConnection, 0, "Set Envoy HTTP option max_requests_per_connection. Default 0 (disable)")
	regOpts.BindEnv(option.ProxyMaxRequestsPerConnection)

	flags.Int64(option.ProxyMaxConnectionDuration, 0, "Set Envoy HTTP option max_connection_duration seconds. Default 0 (disable)")
	regOpts.BindEnv(option.ProxyMaxConnectionDuration)

	flags.Bool(option.DisableEnvoyVersionCheck, false, "Do not perform Envoy binary version check on startup")
	flags.MarkHidden(option.DisableEnvoyVersionCheck)
	// Disable version check if Envoy build is disabled
	regOpts.BindEnvWithLegacyEnvFallback(option.DisableEnvoyVersionCheck, "CILIUM_DISABLE_ENVOY_BUILD")

	flags.Var(option.NewNamedMapOptions(option.FixedIdentityMapping, &option.Config.FixedIdentityMapping, option.Config.FixedIdentityMappingValidator),
		option.FixedIdentityMapping, "Key-value for the fixed identity mapping which allows to use reserved label for fixed identities, e.g. 128=kv-store,129=kube-dns")
	regOpts.BindEnv(option.FixedIdentityMapping)

	flags.Duration(option.IdentityChangeGracePeriod, defaults.IdentityChangeGracePeriod, "Time to wait before using new identity on endpoint identity change")
	regOpts.BindEnv(option.IdentityChangeGracePeriod)

	flags.Duration(option.IdentityRestoreGracePeriod, defaults.IdentityRestoreGracePeriod, "Time to wait before releasing unused restored CIDR identities during agent restart")
	regOpts.BindEnv(option.IdentityRestoreGracePeriod)

	flags.String(option.IdentityAllocationMode, option.IdentityAllocationModeKVstore, "Method to use for identity allocation")
	regOpts.BindEnv(option.IdentityAllocationMode)

	flags.String(option.IPAM, ipamOption.IPAMClusterPool, "Backend to use for IPAM")
	regOpts.BindEnv(option.IPAM)

	flags.String(option.IPv4Range, AutoCIDR, "Per-node IPv4 endpoint prefix, e.g. 10.16.0.0/16")
	regOpts.BindEnv(option.IPv4Range)

	flags.String(option.IPv6Range, AutoCIDR, "Per-node IPv6 endpoint prefix, e.g. fd02:1:1::/96")
	regOpts.BindEnv(option.IPv6Range)

	flags.String(option.IPv6ClusterAllocCIDRName, defaults.IPv6ClusterAllocCIDR, "IPv6 /64 CIDR used to allocate per node endpoint /96 CIDR")
	regOpts.BindEnv(option.IPv6ClusterAllocCIDRName)

	flags.String(option.IPv4ServiceRange, AutoCIDR, "Kubernetes IPv4 services CIDR if not inside cluster prefix")
	regOpts.BindEnv(option.IPv4ServiceRange)

	flags.String(option.IPv6ServiceRange, AutoCIDR, "Kubernetes IPv6 services CIDR if not inside cluster prefix")
	regOpts.BindEnv(option.IPv6ServiceRange)

	flags.Bool(option.K8sEventHandover, defaults.K8sEventHandover, "Enable k8s event handover to kvstore for improved scalability")
	regOpts.BindEnv(option.K8sEventHandover)

	flags.String(option.K8sAPIServer, "", "Kubernetes API server URL")
	regOpts.BindEnv(option.K8sAPIServer)

	flags.String(option.K8sKubeConfigPath, "", "Absolute path of the kubernetes kubeconfig file")
	regOpts.BindEnv(option.K8sKubeConfigPath)

	flags.String(option.K8sNamespaceName, "", "Name of the Kubernetes namespace in which Cilium is deployed in")
	regOpts.BindEnv(option.K8sNamespaceName)

	flags.String(option.AgentNotReadyNodeTaintKeyName, defaults.AgentNotReadyNodeTaint, "Key of the taint indicating that Cilium is not ready on the node")
	regOpts.BindEnv(option.AgentNotReadyNodeTaintKeyName)

	flags.Bool(option.JoinClusterName, false, "Join a Cilium cluster via kvstore registration")
	regOpts.BindEnv(option.JoinClusterName)

	flags.Bool(option.K8sRequireIPv4PodCIDRName, false, "Require IPv4 PodCIDR to be specified in node resource")
	regOpts.BindEnv(option.K8sRequireIPv4PodCIDRName)

	flags.Bool(option.K8sRequireIPv6PodCIDRName, false, "Require IPv6 PodCIDR to be specified in node resource")
	regOpts.BindEnv(option.K8sRequireIPv6PodCIDRName)

	flags.Uint(option.K8sServiceCacheSize, defaults.K8sServiceCacheSize, "Cilium service cache size for kubernetes")
	regOpts.BindEnv(option.K8sServiceCacheSize)
	flags.MarkHidden(option.K8sServiceCacheSize)

	flags.String(option.K8sWatcherEndpointSelector, defaults.K8sWatcherEndpointSelector, "K8s endpoint watcher will watch for these k8s endpoints")
	regOpts.BindEnv(option.K8sWatcherEndpointSelector)

	flags.Bool(option.KeepConfig, false, "When restoring state, keeps containers' configuration in place")
	regOpts.BindEnv(option.KeepConfig)

	flags.String(option.KVStore, "", "Key-value store type")
	regOpts.BindEnv(option.KVStore)

	flags.Duration(option.KVstoreLeaseTTL, defaults.KVstoreLeaseTTL, "Time-to-live for the KVstore lease.")
	flags.MarkHidden(option.KVstoreLeaseTTL)
	regOpts.BindEnv(option.KVstoreLeaseTTL)

	flags.Int(option.KVstoreMaxConsecutiveQuorumErrorsName, defaults.KVstoreMaxConsecutiveQuorumErrors, "Max acceptable kvstore consecutive quorum errors before the agent assumes permanent failure")
	regOpts.BindEnv(option.KVstoreMaxConsecutiveQuorumErrorsName)

	flags.Duration(option.KVstorePeriodicSync, defaults.KVstorePeriodicSync, "Periodic KVstore synchronization interval")
	regOpts.BindEnv(option.KVstorePeriodicSync)

	flags.Duration(option.KVstoreConnectivityTimeout, defaults.KVstoreConnectivityTimeout, "Time after which an incomplete kvstore operation  is considered failed")
	regOpts.BindEnv(option.KVstoreConnectivityTimeout)

	flags.Duration(option.IPAllocationTimeout, defaults.IPAllocationTimeout, "Time after which an incomplete CIDR allocation is considered failed")
	regOpts.BindEnv(option.IPAllocationTimeout)

	flags.Var(option.NewNamedMapOptions(option.KVStoreOpt, &option.Config.KVStoreOpt, nil),
		option.KVStoreOpt, "Key-value store options e.g. etcd.address=127.0.0.1:4001")
	regOpts.BindEnv(option.KVStoreOpt)

	flags.Duration(option.K8sSyncTimeoutName, defaults.K8sSyncTimeout, "Timeout after last K8s event for synchronizing k8s resources before exiting")
	flags.MarkHidden(option.K8sSyncTimeoutName)
	regOpts.BindEnv(option.K8sSyncTimeoutName)

	flags.Duration(option.AllocatorListTimeoutName, defaults.AllocatorListTimeout, "Timeout for listing allocator state before exiting")
	regOpts.BindEnv(option.AllocatorListTimeoutName)

	flags.String(option.LabelPrefixFile, "", "Valid label prefixes file path")
	regOpts.BindEnv(option.LabelPrefixFile)

	flags.StringSlice(option.Labels, []string{}, "List of label prefixes used to determine identity of an endpoint")
	regOpts.BindEnv(option.Labels)

	flags.String(option.KubeProxyReplacement, option.KubeProxyReplacementPartial, fmt.Sprintf(
		"enable only selected features (will panic if any selected feature cannot be enabled) (%q), "+
			"or enable all features (will panic if any feature cannot be enabled) (%q), "+
			"or completely disable it (ignores any selected feature) (%q)",
		option.KubeProxyReplacementPartial, option.KubeProxyReplacementStrict,
		option.KubeProxyReplacementDisabled))
	regOpts.BindEnv(option.KubeProxyReplacement)

	flags.String(option.KubeProxyReplacementHealthzBindAddr, defaults.KubeProxyReplacementHealthzBindAddr, "The IP address with port for kube-proxy replacement health check server to serve on (set to '0.0.0.0:10256' for all IPv4 interfaces and '[::]:10256' for all IPv6 interfaces). Set empty to disable.")
	regOpts.BindEnv(option.KubeProxyReplacementHealthzBindAddr)

	flags.Bool(option.EnableHostPort, true, fmt.Sprintf("Enable k8s hostPort mapping feature (requires enabling %s)", option.EnableNodePort))
	regOpts.BindEnv(option.EnableHostPort)

	flags.Bool(option.EnableNodePort, false, "Enable NodePort type services by Cilium")
	regOpts.BindEnv(option.EnableNodePort)

	flags.Bool(option.EnableSVCSourceRangeCheck, true, "Enable check of service source ranges (currently, only for LoadBalancer)")
	regOpts.BindEnv(option.EnableSVCSourceRangeCheck)

	flags.String(option.AddressScopeMax, fmt.Sprintf("%d", defaults.AddressScopeMax), "Maximum local address scope for ipcache to consider host addresses")
	flags.MarkHidden(option.AddressScopeMax)
	regOpts.BindEnv(option.AddressScopeMax)

	flags.Bool(option.EnableBandwidthManager, false, "Enable BPF bandwidth manager")
	regOpts.BindEnv(option.EnableBandwidthManager)

	flags.Bool(option.EnableBBR, false, "Enable BBR for the bandwidth manager")
	regOpts.BindEnv(option.EnableBBR)

	flags.Bool(option.EnableRecorder, false, "Enable BPF datapath pcap recorder")
	regOpts.BindEnv(option.EnableRecorder)

	flags.Bool(option.EnableLocalRedirectPolicy, false, "Enable Local Redirect Policy")
	regOpts.BindEnv(option.EnableLocalRedirectPolicy)

	flags.Bool(option.EnableMKE, false, "Enable BPF kube-proxy replacement for MKE environments")
	flags.MarkHidden(option.EnableMKE)
	regOpts.BindEnv(option.EnableMKE)

	flags.String(option.CgroupPathMKE, "", "Cgroup v1 net_cls mount path for MKE environments")
	flags.MarkHidden(option.CgroupPathMKE)
	regOpts.BindEnv(option.CgroupPathMKE)

	flags.String(option.NodePortMode, option.NodePortModeSNAT, "BPF NodePort mode (\"snat\", \"dsr\", \"hybrid\")")
	flags.MarkHidden(option.NodePortMode)
	regOpts.BindEnv(option.NodePortMode)

	flags.String(option.NodePortAlg, option.NodePortAlgRandom, "BPF load balancing algorithm (\"random\", \"maglev\")")
	flags.MarkHidden(option.NodePortAlg)
	regOpts.BindEnv(option.NodePortAlg)

	flags.String(option.NodePortAcceleration, option.NodePortAccelerationDisabled, fmt.Sprintf(
		"BPF NodePort acceleration via XDP (\"%s\", \"%s\")",
		option.NodePortAccelerationNative, option.NodePortAccelerationDisabled))
	flags.MarkHidden(option.NodePortAcceleration)
	regOpts.BindEnv(option.NodePortAcceleration)

	flags.String(option.LoadBalancerMode, option.NodePortModeSNAT, "BPF load balancing mode (\"snat\", \"dsr\", \"hybrid\")")
	regOpts.BindEnv(option.LoadBalancerMode)

	flags.String(option.LoadBalancerAlg, option.NodePortAlgRandom, "BPF load balancing algorithm (\"random\", \"maglev\")")
	regOpts.BindEnv(option.LoadBalancerAlg)

	flags.String(option.LoadBalancerDSRDispatch, option.DSRDispatchOption, "BPF load balancing DSR dispatch method (\"opt\", \"ipip\")")
	regOpts.BindEnv(option.LoadBalancerDSRDispatch)

	flags.String(option.LoadBalancerDSRL4Xlate, option.DSRL4XlateFrontend, "BPF load balancing DSR L4 DNAT method for IPIP (\"frontend\", \"backend\")")
	regOpts.BindEnv(option.LoadBalancerDSRL4Xlate)

	flags.String(option.LoadBalancerRSSv4CIDR, "", "BPF load balancing RSS outer source IPv4 CIDR prefix for IPIP")
	regOpts.BindEnv(option.LoadBalancerRSSv4CIDR)

	flags.String(option.LoadBalancerRSSv6CIDR, "", "BPF load balancing RSS outer source IPv6 CIDR prefix for IPIP")
	regOpts.BindEnv(option.LoadBalancerRSSv6CIDR)

	flags.String(option.LoadBalancerAcceleration, option.NodePortAccelerationDisabled, fmt.Sprintf(
		"BPF load balancing acceleration via XDP (\"%s\", \"%s\")",
		option.NodePortAccelerationNative, option.NodePortAccelerationDisabled))
	regOpts.BindEnv(option.LoadBalancerAcceleration)

	flags.Uint(option.MaglevTableSize, maglev.DefaultTableSize, "Maglev per service backend table size (parameter M)")
	regOpts.BindEnv(option.MaglevTableSize)

	flags.String(option.MaglevHashSeed, maglev.DefaultHashSeed, "Maglev cluster-wide hash seed (base64 encoded)")
	regOpts.BindEnv(option.MaglevHashSeed)

	flags.Bool(option.EnableAutoProtectNodePortRange, true,
		"Append NodePort range to net.ipv4.ip_local_reserved_ports if it overlaps "+
			"with ephemeral port range (net.ipv4.ip_local_port_range)")
	regOpts.BindEnv(option.EnableAutoProtectNodePortRange)

	flags.StringSlice(option.NodePortRange, []string{fmt.Sprintf("%d", option.NodePortMinDefault), fmt.Sprintf("%d", option.NodePortMaxDefault)}, "Set the min/max NodePort port range")
	regOpts.BindEnv(option.NodePortRange)

	flags.Bool(option.NodePortBindProtection, true, "Reject application bind(2) requests to service ports in the NodePort range")
	regOpts.BindEnv(option.NodePortBindProtection)

	flags.Bool(option.EnableSessionAffinity, false, "Enable support for service session affinity")
	regOpts.BindEnv(option.EnableSessionAffinity)

	flags.Bool(option.EnableServiceTopology, false, "Enable support for service topology aware hints")
	regOpts.BindEnv(option.EnableServiceTopology)

	flags.Bool(option.EnableIdentityMark, true, "Enable setting identity mark for local traffic")
	regOpts.BindEnv(option.EnableIdentityMark)

	flags.Bool(option.EnableHostFirewall, false, "Enable host network policies")
	regOpts.BindEnv(option.EnableHostFirewall)

	flags.String(option.IPv4NativeRoutingCIDR, "", "Allows to explicitly specify the IPv4 CIDR for native routing. "+
		"When specified, Cilium assumes networking for this CIDR is preconfigured and hands traffic destined for that range to the Linux network stack without applying any SNAT. "+
		"Generally speaking, specifying a native routing CIDR implies that Cilium can depend on the underlying networking stack to route packets to their destination. "+
		"To offer a concrete example, if Cilium is configured to use direct routing and the Kubernetes CIDR is included in the native routing CIDR, the user must configure the routes to reach pods, either manually or by setting the auto-direct-node-routes flag.")
	regOpts.BindEnv(option.IPv4NativeRoutingCIDR)

	flags.String(option.IPv6NativeRoutingCIDR, "", "Allows to explicitly specify the IPv6 CIDR for native routing. "+
		"When specified, Cilium assumes networking for this CIDR is preconfigured and hands traffic destined for that range to the Linux network stack without applying any SNAT. "+
		"Generally speaking, specifying a native routing CIDR implies that Cilium can depend on the underlying networking stack to route packets to their destination. "+
		"To offer a concrete example, if Cilium is configured to use direct routing and the Kubernetes CIDR is included in the native routing CIDR, the user must configure the routes to reach pods, either manually or by setting the auto-direct-node-routes flag.")
	regOpts.BindEnv(option.IPv6NativeRoutingCIDR)

	flags.String(option.LibDir, defaults.LibraryPath, "Directory path to store runtime build environment")
	regOpts.BindEnv(option.LibDir)

	flags.StringSlice(option.LogDriver, []string{}, "Logging endpoints to use for example syslog")
	regOpts.BindEnv(option.LogDriver)

	flags.Var(option.NewNamedMapOptions(option.LogOpt, &option.Config.LogOpt, nil),
		option.LogOpt, `Log driver options for cilium-agent, `+
			`configmap example for syslog driver: {"syslog.level":"info","syslog.facility":"local5","syslog.tag":"cilium-agent"}`)
	regOpts.BindEnv(option.LogOpt)

	flags.Bool(option.LogSystemLoadConfigName, false, "Enable periodic logging of system load")
	regOpts.BindEnv(option.LogSystemLoadConfigName)

	flags.String(option.LoopbackIPv4, defaults.LoopbackIPv4, "IPv4 address for service loopback SNAT")
	regOpts.BindEnv(option.LoopbackIPv4)

	flags.Bool(option.EnableIPv4Masquerade, true, "Masquerade IPv4 traffic from endpoints leaving the host")
	regOpts.BindEnv(option.EnableIPv4Masquerade)

	flags.Bool(option.EnableIPv6Masquerade, true, "Masquerade IPv6 traffic from endpoints leaving the host")
	regOpts.BindEnv(option.EnableIPv6Masquerade)

	flags.Bool(option.EnableBPFMasquerade, false, "Masquerade packets from endpoints leaving the host with BPF instead of iptables")
	regOpts.BindEnv(option.EnableBPFMasquerade)

	flags.String(option.DeriveMasqIPAddrFromDevice, "", "Device name from which Cilium derives the IP addr for BPF masquerade")
	flags.MarkHidden(option.DeriveMasqIPAddrFromDevice)
	regOpts.BindEnv(option.DeriveMasqIPAddrFromDevice)

	flags.Bool(option.EnableIPMasqAgent, false, "Enable BPF ip-masq-agent")
	regOpts.BindEnv(option.EnableIPMasqAgent)

	flags.Bool(option.EnableIPv6BIGTCP, false, "Enable IPv6 BIG TCP option which increases device's maximum GRO/GSO limits")
	regOpts.BindEnv(option.EnableIPv6BIGTCP)

	flags.Bool(option.EnableIPv4EgressGateway, false, "Enable egress gateway for IPv4")
	regOpts.BindEnv(option.EnableIPv4EgressGateway)

	flags.Bool(option.InstallEgressGatewayRoutes, false, "Install egress gateway IP rules and routes in order to properly steer egress gateway traffic to the correct ENI interface")
	regOpts.BindEnv(option.InstallEgressGatewayRoutes)

	flags.Bool(option.EnableEnvoyConfig, false, "Enable Envoy Config CRDs")
	regOpts.BindEnv(option.EnableEnvoyConfig)

	flags.Duration(option.EnvoyConfigTimeout, defaults.EnvoyConfigTimeout, "Timeout duration for Envoy Config acknowledgements")
	regOpts.BindEnv(option.EnvoyConfigTimeout)

	flags.String(option.IPMasqAgentConfigPath, "/etc/config/ip-masq-agent", "ip-masq-agent configuration file path")
	regOpts.BindEnv(option.IPMasqAgentConfigPath)

	flags.Bool(option.InstallIptRules, true, "Install base iptables rules for cilium to mainly interact with kube-proxy (and masquerading)")
	regOpts.BindEnv(option.InstallIptRules)

	flags.Duration(option.IPTablesLockTimeout, 5*time.Second, "Time to pass to each iptables invocation to wait for xtables lock acquisition")
	regOpts.BindEnv(option.IPTablesLockTimeout)

	flags.Bool(option.IPTablesRandomFully, false, "Set iptables flag random-fully on masquerading rules")
	regOpts.BindEnv(option.IPTablesRandomFully)

	flags.Int(option.MaxCtrlIntervalName, 0, "Maximum interval (in seconds) between controller runs. Zero is no limit.")
	flags.MarkHidden(option.MaxCtrlIntervalName)
	regOpts.BindEnv(option.MaxCtrlIntervalName)

	flags.StringSlice(option.Metrics, []string{}, "Metrics that should be enabled or disabled from the default metric list. (+metric_foo to enable metric_foo , -metric_bar to disable metric_bar)")
	regOpts.BindEnv(option.Metrics)

	flags.Bool(option.EnableMonitorName, true, "Enable the monitor unix domain socket server")
	regOpts.BindEnv(option.EnableMonitorName)

	flags.String(option.MonitorAggregationName, "None",
		"Level of monitor aggregation for traces from the datapath")
	regOpts.BindEnvWithLegacyEnvFallback(option.MonitorAggregationName, "CILIUM_MONITOR_AGGREGATION_LEVEL")

	flags.Int(option.MonitorQueueSizeName, 0, "Size of the event queue when reading monitor events")
	regOpts.BindEnv(option.MonitorQueueSizeName)

	flags.Int(option.MTUName, 0, "Overwrite auto-detected MTU of underlying network")
	regOpts.BindEnv(option.MTUName)

	flags.String(option.ProcFs, "/proc", "Root's proc filesystem path")
	regOpts.BindEnv(option.ProcFs)

	flags.Int(option.RouteMetric, 0, "Overwrite the metric used by cilium when adding routes to its 'cilium_host' device")
	regOpts.BindEnv(option.RouteMetric)

	flags.Bool(option.PrependIptablesChainsName, true, "Prepend custom iptables chains instead of appending")
	regOpts.BindEnvWithLegacyEnvFallback(option.PrependIptablesChainsName, "CILIUM_PREPEND_IPTABLES_CHAIN")

	flags.String(option.IPv6NodeAddr, "auto", "IPv6 address of node")
	regOpts.BindEnv(option.IPv6NodeAddr)

	flags.String(option.IPv4NodeAddr, "auto", "IPv4 address of node")
	regOpts.BindEnv(option.IPv4NodeAddr)

	flags.String(option.ReadCNIConfiguration, "", "Read to the CNI configuration at specified path to extract per node configuration")
	regOpts.BindEnv(option.ReadCNIConfiguration)

	flags.Bool(option.Restore, true, "Restores state, if possible, from previous daemon")
	regOpts.BindEnv(option.Restore)

	flags.String(option.SidecarIstioProxyImage, k8s.DefaultSidecarIstioProxyImageRegexp,
		"Regular expression matching compatible Istio sidecar istio-proxy container image names")
	regOpts.BindEnv(option.SidecarIstioProxyImage)

	flags.Bool(option.SingleClusterRouteName, false,
		"Use a single cluster route instead of per node routes")
	regOpts.BindEnv(option.SingleClusterRouteName)

	flags.String(option.SocketPath, defaults.SockPath, "Sets daemon's socket path to listen for connections")
	regOpts.BindEnv(option.SocketPath)

	flags.String(option.StateDir, defaults.RuntimePath, "Directory path to store runtime state")
	regOpts.BindEnv(option.StateDir)

	flags.StringP(option.TunnelName, "t", "", fmt.Sprintf("Tunnel mode {%s} (default \"vxlan\" for the \"veth\" datapath mode)", option.GetTunnelModes()))
	regOpts.BindEnv(option.TunnelName)

	flags.Int(option.TunnelPortName, 0, fmt.Sprintf("Tunnel port (default %d for \"vxlan\" and %d for \"geneve\")", defaults.TunnelPortVXLAN, defaults.TunnelPortGeneve))
	regOpts.BindEnv(option.TunnelPortName)

	flags.Int(option.TracePayloadlen, 128, "Length of payload to capture when tracing")
	regOpts.BindEnv(option.TracePayloadlen)

	flags.Bool(option.Version, false, "Print version information")
	regOpts.BindEnv(option.Version)

	flags.Bool(option.PProf, false, "Enable serving the pprof debugging API")
	regOpts.BindEnv(option.PProf)

	flags.Int(option.PProfPort, 6060, "Port that the pprof listens on")
	regOpts.BindEnv(option.PProfPort)

	flags.Bool(option.EnableXDPPrefilter, false, "Enable XDP prefiltering")
	regOpts.BindEnv(option.EnableXDPPrefilter)

	flags.Bool(option.PreAllocateMapsName, defaults.PreAllocateMaps, "Enable BPF map pre-allocation")
	regOpts.BindEnv(option.PreAllocateMapsName)

	// We expect only one of the possible variables to be filled. The evaluation order is:
	// --prometheus-serve-addr, CILIUM_PROMETHEUS_SERVE_ADDR, then PROMETHEUS_SERVE_ADDR
	// The second environment variable (without the CILIUM_ prefix) is here to
	// handle the case where someone uses a new image with an older spec, and the
	// older spec used the older variable name.
	flags.String(option.PrometheusServeAddr, ":9962", "IP:Port on which to serve prometheus metrics (pass \":Port\" to bind on all interfaces, \"\" is off)")
	regOpts.BindEnvWithLegacyEnvFallback(option.PrometheusServeAddr, "PROMETHEUS_SERVE_ADDR")

	flags.Int(option.CTMapEntriesGlobalTCPName, option.CTMapEntriesGlobalTCPDefault, "Maximum number of entries in TCP CT table")
	regOpts.BindEnvWithLegacyEnvFallback(option.CTMapEntriesGlobalTCPName, "CILIUM_GLOBAL_CT_MAX_TCP")

	flags.String(option.CertsDirectory, defaults.CertsDirectory, "Root directory to find certificates specified in L7 TLS policy enforcement")
	regOpts.BindEnv(option.CertsDirectory)

	flags.Int(option.CTMapEntriesGlobalAnyName, option.CTMapEntriesGlobalAnyDefault, "Maximum number of entries in non-TCP CT table")
	regOpts.BindEnvWithLegacyEnvFallback(option.CTMapEntriesGlobalAnyName, "CILIUM_GLOBAL_CT_MAX_ANY")

	flags.Duration(option.CTMapEntriesTimeoutTCPName, 21600*time.Second, "Timeout for established entries in TCP CT table")
	regOpts.BindEnv(option.CTMapEntriesTimeoutTCPName)

	flags.Duration(option.CTMapEntriesTimeoutAnyName, 60*time.Second, "Timeout for entries in non-TCP CT table")
	regOpts.BindEnv(option.CTMapEntriesTimeoutAnyName)

	flags.Duration(option.CTMapEntriesTimeoutSVCTCPName, 21600*time.Second, "Timeout for established service entries in TCP CT table")
	regOpts.BindEnv(option.CTMapEntriesTimeoutSVCTCPName)

	flags.Duration(option.CTMapEntriesTimeoutSVCTCPGraceName, 60*time.Second, "Timeout for graceful shutdown of service entries in TCP CT table")
	regOpts.BindEnv(option.CTMapEntriesTimeoutSVCTCPGraceName)

	flags.Duration(option.CTMapEntriesTimeoutSVCAnyName, 60*time.Second, "Timeout for service entries in non-TCP CT table")
	regOpts.BindEnv(option.CTMapEntriesTimeoutSVCAnyName)

	flags.Duration(option.CTMapEntriesTimeoutSYNName, 60*time.Second, "Establishment timeout for entries in TCP CT table")
	regOpts.BindEnv(option.CTMapEntriesTimeoutSYNName)

	flags.Duration(option.CTMapEntriesTimeoutFINName, 10*time.Second, "Teardown timeout for entries in TCP CT table")
	regOpts.BindEnv(option.CTMapEntriesTimeoutFINName)

	flags.Duration(option.MonitorAggregationInterval, 5*time.Second, "Monitor report interval when monitor aggregation is enabled")
	regOpts.BindEnv(option.MonitorAggregationInterval)

	flags.StringSlice(option.MonitorAggregationFlags, option.MonitorAggregationFlagsDefault, "TCP flags that trigger monitor reports when monitor aggregation is enabled")
	regOpts.BindEnv(option.MonitorAggregationFlags)

	flags.Int(option.NATMapEntriesGlobalName, option.NATMapEntriesGlobalDefault, "Maximum number of entries for the global BPF NAT table")
	regOpts.BindEnv(option.NATMapEntriesGlobalName)

	flags.Int(option.NeighMapEntriesGlobalName, option.NATMapEntriesGlobalDefault, "Maximum number of entries for the global BPF neighbor table")
	regOpts.BindEnv(option.NeighMapEntriesGlobalName)

	flags.Int(option.PolicyMapEntriesName, policymap.MaxEntries, "Maximum number of entries in endpoint policy map (per endpoint)")
	regOpts.BindEnv(option.PolicyMapEntriesName)

	flags.Int(option.SockRevNatEntriesName, option.SockRevNATMapEntriesDefault, "Maximum number of entries for the SockRevNAT BPF map")
	regOpts.BindEnv(option.SockRevNatEntriesName)

	flags.Float64(option.MapEntriesGlobalDynamicSizeRatioName, 0.0, "Ratio (0.0-1.0) of total system memory to use for dynamic sizing of CT, NAT and policy BPF maps. Set to 0.0 to disable dynamic BPF map sizing (default: 0.0)")
	regOpts.BindEnv(option.MapEntriesGlobalDynamicSizeRatioName)

	flags.String(option.CMDRef, "", "Path to cmdref output directory")
	flags.MarkHidden(option.CMDRef)
	regOpts.BindEnv(option.CMDRef)

	flags.Int(option.GopsPort, defaults.GopsPortAgent, "Port for gops server to listen on")
	regOpts.BindEnv(option.GopsPort)

	flags.Int(option.ToFQDNsMinTTL, 0, fmt.Sprintf("The minimum time, in seconds, to use DNS data for toFQDNs policies. (default %d )", defaults.ToFQDNsMinTTL))
	regOpts.BindEnv(option.ToFQDNsMinTTL)

	flags.Int(option.ToFQDNsProxyPort, 0, "Global port on which the in-agent DNS proxy should listen. Default 0 is a OS-assigned port.")
	regOpts.BindEnv(option.ToFQDNsProxyPort)

	flags.StringVar(&option.Config.FQDNRejectResponse, option.FQDNRejectResponseCode, option.FQDNProxyDenyWithRefused, fmt.Sprintf("DNS response code for rejecting DNS requests, available options are '%v'", option.FQDNRejectOptions))
	regOpts.BindEnv(option.FQDNRejectResponseCode)

	flags.Int(option.ToFQDNsMaxIPsPerHost, defaults.ToFQDNsMaxIPsPerHost, "Maximum number of IPs to maintain per FQDN name for each endpoint")
	regOpts.BindEnv(option.ToFQDNsMaxIPsPerHost)

	flags.Int(option.DNSMaxIPsPerRestoredRule, defaults.DNSMaxIPsPerRestoredRule, "Maximum number of IPs to maintain for each restored DNS rule")
	regOpts.BindEnv(option.DNSMaxIPsPerRestoredRule)

	flags.Bool(option.DNSPolicyUnloadOnShutdown, false, "Unload DNS policy rules on graceful shutdown")
	regOpts.BindEnv(option.DNSPolicyUnloadOnShutdown)

	flags.Int(option.ToFQDNsMaxDeferredConnectionDeletes, defaults.ToFQDNsMaxDeferredConnectionDeletes, "Maximum number of IPs to retain for expired DNS lookups with still-active connections")
	regOpts.BindEnv(option.ToFQDNsMaxDeferredConnectionDeletes)

	flags.DurationVar(&option.Config.ToFQDNsIdleConnectionGracePeriod, option.ToFQDNsIdleConnectionGracePeriod, defaults.ToFQDNsIdleConnectionGracePeriod, "Time during which idle but previously active connections with expired DNS lookups are still considered alive (default 0s)")
	regOpts.BindEnv(option.ToFQDNsIdleConnectionGracePeriod)

	flags.DurationVar(&option.Config.FQDNProxyResponseMaxDelay, option.FQDNProxyResponseMaxDelay, 100*time.Millisecond, "The maximum time the DNS proxy holds an allowed DNS response before sending it along. Responses are sent as soon as the datapath is updated with the new IP information.")
	regOpts.BindEnv(option.FQDNProxyResponseMaxDelay)

	flags.Int(option.FQDNRegexCompileLRUSize, defaults.FQDNRegexCompileLRUSize, "Size of the FQDN regex compilation LRU. Useful for heavy but repeated DNS L7 rules with MatchName or MatchPattern")
	flags.MarkHidden(option.FQDNRegexCompileLRUSize)
	regOpts.BindEnv(option.FQDNRegexCompileLRUSize)

	flags.String(option.ToFQDNsPreCache, defaults.ToFQDNsPreCache, "DNS cache data at this path is preloaded on agent startup")
	regOpts.BindEnv(option.ToFQDNsPreCache)

	flags.Bool(option.ToFQDNsEnableDNSCompression, defaults.ToFQDNsEnableDNSCompression, "Allow the DNS proxy to compress responses to endpoints that are larger than 512 Bytes or the EDNS0 option, if present")
	regOpts.BindEnv(option.ToFQDNsEnableDNSCompression)

	flags.Int(option.DNSProxyConcurrencyLimit, 0, "Limit concurrency of DNS message processing")
	regOpts.BindEnv(option.DNSProxyConcurrencyLimit)

	flags.Duration(option.DNSProxyConcurrencyProcessingGracePeriod, 0, "Grace time to wait when DNS proxy concurrent limit has been reached during DNS message processing")
	regOpts.BindEnv(option.DNSProxyConcurrencyProcessingGracePeriod)

	flags.Int(option.PolicyQueueSize, defaults.PolicyQueueSize, "size of queues for policy-related events")
	regOpts.BindEnv(option.PolicyQueueSize)

	flags.Int(option.EndpointQueueSize, defaults.EndpointQueueSize, "size of EventQueue per-endpoint")
	regOpts.BindEnv(option.EndpointQueueSize)

	flags.Duration(option.EndpointGCInterval, 5*time.Minute, "Periodically monitor local endpoint health via link status on this interval and garbage collect them if they become unhealthy, set to 0 to disable")
	flags.MarkHidden(option.EndpointGCInterval)
	regOpts.BindEnv(option.EndpointGCInterval)

	flags.Bool(option.SelectiveRegeneration, true, "only regenerate endpoints which need to be regenerated upon policy changes")
	flags.MarkHidden(option.SelectiveRegeneration)
	regOpts.BindEnv(option.SelectiveRegeneration)

	flags.String(option.WriteCNIConfigurationWhenReady, "", fmt.Sprintf("Write the CNI configuration as specified via --%s to path when agent is ready", option.ReadCNIConfiguration))
	regOpts.BindEnv(option.WriteCNIConfigurationWhenReady)

	flags.Duration(option.PolicyTriggerInterval, defaults.PolicyTriggerInterval, "Time between triggers of policy updates (regenerations for all endpoints)")
	flags.MarkHidden(option.PolicyTriggerInterval)
	regOpts.BindEnv(option.PolicyTriggerInterval)

	flags.Bool(option.DisableCNPStatusUpdates, false, `Do not send CNP NodeStatus updates to the Kubernetes api-server (recommended to run with "cnp-node-status-gc-interval=0" in cilium-operator)`)
	regOpts.BindEnv(option.DisableCNPStatusUpdates)

	flags.Bool(option.PolicyAuditModeArg, false, "Enable policy audit (non-drop) mode")
	regOpts.BindEnv(option.PolicyAuditModeArg)

	flags.Bool(option.EnableHubble, false, "Enable hubble server")
	regOpts.BindEnv(option.EnableHubble)

	flags.String(option.HubbleSocketPath, defaults.HubbleSockPath, "Set hubble's socket path to listen for connections")
	regOpts.BindEnv(option.HubbleSocketPath)

	flags.String(option.HubbleListenAddress, "", `An additional address for Hubble server to listen to, e.g. ":4244"`)
	regOpts.BindEnv(option.HubbleListenAddress)

	flags.Bool(option.HubbleTLSDisabled, false, "Allow Hubble server to run on the given listen address without TLS.")
	regOpts.BindEnv(option.HubbleTLSDisabled)

	flags.String(option.HubbleTLSCertFile, "", "Path to the public key file for the Hubble server. The file must contain PEM encoded data.")
	regOpts.BindEnv(option.HubbleTLSCertFile)

	flags.String(option.HubbleTLSKeyFile, "", "Path to the private key file for the Hubble server. The file must contain PEM encoded data.")
	regOpts.BindEnv(option.HubbleTLSKeyFile)

	flags.StringSlice(option.HubbleTLSClientCAFiles, []string{}, "Paths to one or more public key files of client CA certificates to use for TLS with mutual authentication (mTLS). The files must contain PEM encoded data. When provided, this option effectively enables mTLS.")
	regOpts.BindEnv(option.HubbleTLSClientCAFiles)

	flags.Int(option.HubbleEventBufferCapacity, observeroption.Default.MaxFlows.AsInt(), "Capacity of Hubble events buffer. The provided value must be one less than an integer power of two and no larger than 65535 (ie: 1, 3, ..., 2047, 4095, ..., 65535)")
	regOpts.BindEnv(option.HubbleEventBufferCapacity)

	flags.Int(option.HubbleEventQueueSize, 0, "Buffer size of the channel to receive monitor events.")
	regOpts.BindEnv(option.HubbleEventQueueSize)

	flags.String(option.HubbleMetricsServer, "", "Address to serve Hubble metrics on.")
	regOpts.BindEnv(option.HubbleMetricsServer)

	flags.StringSlice(option.HubbleMetrics, []string{}, "List of Hubble metrics to enable.")
	regOpts.BindEnv(option.HubbleMetrics)

	flags.String(option.HubbleExportFilePath, exporteroption.Default.Path, "Filepath to write Hubble events to.")
	regOpts.BindEnv(option.HubbleExportFilePath)

	flags.Int(option.HubbleExportFileMaxSizeMB, exporteroption.Default.MaxSizeMB, "Size in MB at which to rotate Hubble export file.")
	regOpts.BindEnv(option.HubbleExportFileMaxSizeMB)

	flags.Int(option.HubbleExportFileMaxBackups, exporteroption.Default.MaxBackups, "Number of rotated Hubble export files to keep.")
	regOpts.BindEnv(option.HubbleExportFileMaxBackups)

	flags.Bool(option.HubbleExportFileCompress, exporteroption.Default.Compress, "Compress rotated Hubble export files.")
	regOpts.BindEnv(option.HubbleExportFileCompress)

	flags.Bool(option.EnableHubbleRecorderAPI, true, "Enable the Hubble recorder API")
	regOpts.BindEnv(option.EnableHubbleRecorderAPI)

	flags.String(option.HubbleRecorderStoragePath, defaults.HubbleRecorderStoragePath, "Directory in which pcap files created via the Hubble Recorder API are stored")
	regOpts.BindEnv(option.HubbleRecorderStoragePath)

	flags.Int(option.HubbleRecorderSinkQueueSize, defaults.HubbleRecorderSinkQueueSize, "Queue size of each Hubble recorder sink")
	regOpts.BindEnv(option.HubbleRecorderSinkQueueSize)

	flags.StringSlice(option.DisableIptablesFeederRules, []string{}, "Chains to ignore when installing feeder rules.")
	regOpts.BindEnv(option.DisableIptablesFeederRules)

	flags.Duration(option.K8sHeartbeatTimeout, 30*time.Second, "Configures the timeout for api-server heartbeat, set to 0 to disable")
	regOpts.BindEnv(option.K8sHeartbeatTimeout)

	flags.Bool(option.EnableIPv4FragmentsTrackingName, defaults.EnableIPv4FragmentsTracking, "Enable IPv4 fragments tracking for L4-based lookups")
	regOpts.BindEnv(option.EnableIPv4FragmentsTrackingName)

	flags.Int(option.FragmentsMapEntriesName, defaults.FragmentsMapEntries, "Maximum number of entries in fragments tracking map")
	regOpts.BindEnv(option.FragmentsMapEntriesName)

	flags.Int(option.LBMapEntriesName, lbmap.DefaultMaxEntries, "Maximum number of entries in Cilium BPF lbmap")
	regOpts.BindEnv(option.LBMapEntriesName)

	flags.Int(option.LBServiceMapMaxEntries, 0, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for services (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBServiceMapMaxEntries)
	regOpts.BindEnv(option.LBServiceMapMaxEntries)

	flags.Int(option.LBBackendMapMaxEntries, 0, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for service backends (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBBackendMapMaxEntries)
	regOpts.BindEnv(option.LBBackendMapMaxEntries)

	flags.Int(option.LBRevNatMapMaxEntries, 0, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for reverse NAT (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBRevNatMapMaxEntries)
	regOpts.BindEnv(option.LBRevNatMapMaxEntries)

	flags.Int(option.LBAffinityMapMaxEntries, 0, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for session affinities (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBAffinityMapMaxEntries)
	regOpts.BindEnv(option.LBAffinityMapMaxEntries)

	flags.Int(option.LBSourceRangeMapMaxEntries, 0, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for source ranges (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBSourceRangeMapMaxEntries)
	regOpts.BindEnv(option.LBSourceRangeMapMaxEntries)

	flags.Int(option.LBMaglevMapMaxEntries, 0, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for maglev (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBMaglevMapMaxEntries)
	regOpts.BindEnv(option.LBMaglevMapMaxEntries)

	flags.String(option.LocalRouterIPv4, "", "Link-local IPv4 used for Cilium's router devices")
	regOpts.BindEnv(option.LocalRouterIPv4)

	flags.String(option.LocalRouterIPv6, "", "Link-local IPv6 used for Cilium's router devices")
	regOpts.BindEnv(option.LocalRouterIPv6)

	flags.String(option.K8sServiceProxyName, "", "Value of K8s service-proxy-name label for which Cilium handles the services (empty = all services without service.kubernetes.io/service-proxy-name label)")
	regOpts.BindEnv(option.K8sServiceProxyName)

	flags.Var(option.NewNamedMapOptions(option.APIRateLimitName, &option.Config.APIRateLimit, nil), option.APIRateLimitName, "API rate limiting configuration (example: --rate-limit endpoint-create=rate-limit:10/m,rate-burst:2)")
	regOpts.BindEnv(option.APIRateLimitName)

	flags.Duration(option.CRDWaitTimeout, 5*time.Minute, "Cilium will exit if CRDs are not available within this duration upon startup")
	regOpts.BindEnv(option.CRDWaitTimeout)

	flags.Bool(option.EgressMultiHomeIPRuleCompat, false,
		"Offset routing table IDs under ENI IPAM mode to avoid collisions with reserved table IDs. If false, the offset is performed (new scheme), otherwise, the old scheme stays in-place.")
	regOpts.BindEnv(option.EgressMultiHomeIPRuleCompat)

	flags.Bool(option.InstallNoConntrackIptRules, defaults.InstallNoConntrackIptRules, "Install Iptables rules to skip netfilter connection tracking on all pod traffic. This option is only effective when Cilium is running in direct routing and full KPR mode. Moreover, this option cannot be enabled when Cilium is running in a managed Kubernetes environment or in a chained CNI setup.")
	regOpts.BindEnv(option.InstallNoConntrackIptRules)

	flags.Bool(option.EnableCustomCallsName, false, "Enable tail call hooks for custom eBPF programs")
	regOpts.BindEnv(option.EnableCustomCallsName)

	flags.Bool(option.BGPAnnounceLBIP, false, "Announces service IPs of type LoadBalancer via BGP")
	regOpts.BindEnv(option.BGPAnnounceLBIP)

	flags.Bool(option.BGPAnnouncePodCIDR, false, "Announces the node's pod CIDR via BGP")
	regOpts.BindEnv(option.BGPAnnouncePodCIDR)

	flags.String(option.BGPConfigPath, "/var/lib/cilium/bgp/config.yaml", "Path to file containing the BGP configuration")
	regOpts.BindEnv(option.BGPConfigPath)

	flags.Bool(option.ExternalClusterIPName, false, "Enable external access to ClusterIP services (default false)")
	regOpts.BindEnv(option.ExternalClusterIPName)

	// flags.IntSlice cannot be used due to missing support for appropriate conversion in Viper.
	// See https://github.com/cilium/cilium/pull/20282 for more information.
	flags.StringSlice(option.VLANBPFBypass, []string{}, "List of explicitly allowed VLAN IDs, '0' id will allow all VLAN IDs")
	regOpts.BindEnv(option.VLANBPFBypass)

	flags.Bool(option.EnableICMPRules, true, "Enable ICMP-based rule support for Cilium Network Policies")
	flags.MarkHidden(option.EnableICMPRules)
	regOpts.BindEnv(option.EnableICMPRules)

	flags.Bool(option.BypassIPAvailabilityUponRestore, false, "Bypasses the IP availability error within IPAM upon endpoint restore")
	flags.MarkHidden(option.BypassIPAvailabilityUponRestore)
	regOpts.BindEnv(option.BypassIPAvailabilityUponRestore)

	flags.Bool(option.EnableCiliumEndpointSlice, false, "If set to true, CiliumEndpointSlice feature is enabled and cilium agent watch for CiliumEndpointSlice instead of CiliumEndpoint to update the IPCache.")
	regOpts.BindEnv(option.EnableCiliumEndpointSlice)

	flags.Bool(option.EnableK8sTerminatingEndpoint, true, "Enable auto-detect of terminating endpoint condition")
	regOpts.BindEnv(option.EnableK8sTerminatingEndpoint)

	flags.Bool(option.EnableVTEP, defaults.EnableVTEP, "Enable  VXLAN Tunnel Endpoint (VTEP) Integration (beta)")
	regOpts.BindEnv(option.EnableVTEP)

	flags.StringSlice(option.VtepEndpoint, []string{}, "List of VTEP IP addresses")
	regOpts.BindEnv(option.VtepEndpoint)

	flags.StringSlice(option.VtepCIDR, []string{}, "List of VTEP CIDRs that will be routed towards VTEPs for traffic cluster egress")
	regOpts.BindEnv(option.VtepCIDR)

	flags.String(option.VtepMask, "255.255.255.0", "VTEP CIDR Mask for all VTEP CIDRs")
	regOpts.BindEnv(option.VtepMask)

	flags.StringSlice(option.VtepMAC, []string{}, "List of VTEP MAC addresses for forwarding traffic outside the cluster")
	regOpts.BindEnv(option.VtepMAC)

	flags.Int(option.TCFilterPriority, 1, "Priority of TC BPF filter")
	flags.MarkHidden(option.TCFilterPriority)
	regOpts.BindEnv(option.TCFilterPriority)

	flags.Bool(option.EnableBGPControlPlane, false, "Enable the BGP control plane.")
	regOpts.BindEnv(option.EnableBGPControlPlane)

	Vp.BindPFlags(flags)
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
	var debugDatapath bool

	option.Config.SetMapElementSizes(
		// for the conntrack and NAT element size we assume the largest possible
		// key size, i.e. IPv6 keys
		ctmap.SizeofCtKey6Global+ctmap.SizeofCtEntry,
		nat.SizeofNatKey6+nat.SizeofNatEntry6,
		neighborsmap.SizeofNeighKey6+neighborsmap.SizeOfNeighValue,
		lbmap.SizeofSockRevNat6Key+lbmap.SizeofSockRevNat6Value)

	// Prepopulate option.Config with options from CLI.
	option.Config.Populate(Vp)

	// add hooks after setting up metrics in the option.Config
	logging.DefaultLogger.Hooks.Add(metrics.NewLoggingHook(components.CiliumAgentName))

	// Logging should always be bootstrapped first. Do not add any code above this!
	if err := logging.SetupLogging(option.Config.LogDriver, logging.LogOptions(option.Config.LogOpt), "cilium-agent", option.Config.Debug); err != nil {
		log.Fatal(err)
	}

	regOpts.LogRegisteredOptions(log)

	sysctl.SetProcfs(option.Config.ProcFs)

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
		case argDebugVerboseDatapath:
			log.Debugf("Enabling datapath debug messages")
			debugDatapath = true
		case argDebugVerbosePolicy:
			option.Config.Opts.SetBool(option.DebugPolicy, true)
		default:
			log.Warningf("Unknown verbose debug group: %s", grp)
		}
	}
	// Enable policy debugging if debug is enabled.
	if option.Config.Debug {
		option.Config.Opts.SetBool(option.DebugPolicy, true)
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
	if option.Config.IdentityAllocationMode == option.IdentityAllocationModeCRD && !k8s.IsEnabled() &&
		option.Config.DatapathMode != datapathOption.DatapathModeLBOnly {
		log.Fatal("CRD Identity allocation mode requires k8s to be configured.")
	}

	if option.Config.PProf {
		pprof.Enable(option.Config.PProfPort)
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

	if option.Config.RunDir != defaults.RuntimePath {
		if err := os.MkdirAll(defaults.RuntimePath, defaults.RuntimePathRights); err != nil {
			scopedLog.WithError(err).Fatal("Could not create default runtime directory")
		}
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

	scopedLog = log.WithField(logfields.Path, option.Config.SocketPath)
	socketDir := path.Dir(option.Config.SocketPath)
	if err := os.MkdirAll(socketDir, defaults.RuntimePathRights); err != nil {
		scopedLog.WithError(err).Fatal("Cannot mkdir directory for cilium socket")
	}

	if err := os.Remove(option.Config.SocketPath); !os.IsNotExist(err) && err != nil {
		scopedLog.WithError(err).Fatal("Cannot remove existing Cilium sock")
	}

	// The standard operation is to mount the BPF filesystem to the
	// standard location (/sys/fs/bpf). The user may choose to specify
	// the path to an already mounted filesystem instead. This is
	// useful if the daemon is being round inside a namespace and the
	// BPF filesystem is mapped into the slave namespace.
	bpf.CheckOrMountFS(option.Config.BPFRoot)
	cgroups.CheckOrMountCgrpFS(option.Config.CGroupRoot)

	option.Config.Opts.SetBool(option.Debug, debugDatapath)
	option.Config.Opts.SetBool(option.DebugLB, debugDatapath)
	option.Config.Opts.SetBool(option.DropNotify, true)
	option.Config.Opts.SetBool(option.TraceNotify, true)
	option.Config.Opts.SetBool(option.PolicyVerdictNotify, true)
	option.Config.Opts.SetBool(option.PolicyTracing, option.Config.EnableTracing)
	option.Config.Opts.SetBool(option.ConntrackAccounting, true)
	option.Config.Opts.SetBool(option.ConntrackLocal, false)
	option.Config.Opts.SetBool(option.PolicyAuditMode, option.Config.PolicyAuditMode)

	monitorAggregationLevel, err := option.ParseMonitorAggregationLevel(option.Config.MonitorAggregation)
	if err != nil {
		log.WithError(err).Fatalf("Failed to parse %s", option.MonitorAggregationName)
	}
	option.Config.Opts.SetValidated(option.MonitorAggregation, monitorAggregationLevel)

	policy.SetPolicyEnabled(option.Config.EnablePolicy)
	if option.Config.PolicyAuditMode {
		log.Warningf("%s is enabled. Network policy will not be enforced.", option.PolicyAuditMode)
	}

	if err := identity.AddUserDefinedNumericIdentitySet(option.Config.FixedIdentityMapping); err != nil {
		log.WithError(err).Fatal("Invalid fixed identities provided")
	}

	if !option.Config.EnableIPv4 && !option.Config.EnableIPv6 {
		log.Fatal("Either IPv4 or IPv6 addressing must be enabled")
	}
	if err := labelsfilter.ParseLabelPrefixCfg(option.Config.Labels, option.Config.LabelPrefixFile); err != nil {
		log.WithError(err).Fatal("Unable to parse Label prefix configuration")
	}

	switch option.Config.DatapathMode {
	case datapathOption.DatapathModeVeth:
		if option.Config.Tunnel == "" {
			option.Config.Tunnel = option.TunnelVXLAN
		}
	case datapathOption.DatapathModeLBOnly:
		log.Info("Running in LB-only mode")
		option.Config.LoadBalancerPMTUDiscovery =
			option.Config.NodePortAcceleration != option.NodePortAccelerationDisabled
		option.Config.KubeProxyReplacement = option.KubeProxyReplacementPartial
		option.Config.EnableSocketLB = true
		option.Config.EnableHostPort = false
		option.Config.EnableNodePort = true
		option.Config.EnableExternalIPs = true
		option.Config.Tunnel = option.TunnelDisabled
		option.Config.EnableHealthChecking = false
		option.Config.EnableIPv4Masquerade = false
		option.Config.EnableIPv6Masquerade = false
		option.Config.InstallIptRules = false
		option.Config.EnableL7Proxy = false
	default:
		log.WithField(logfields.DatapathMode, option.Config.DatapathMode).Fatal("Invalid datapath mode")
	}

	if option.Config.EnableL7Proxy && !option.Config.InstallIptRules {
		log.Fatal("L7 proxy requires iptables rules (--install-iptables-rules=\"true\")")
	}

	if option.Config.EnableIPSec && option.Config.TunnelingEnabled() {
		if err := ipsec.ProbeXfrmStateOutputMask(); err != nil {
			log.WithError(err).Fatal("IPSec with tunneling requires support for xfrm state output masks (Linux 4.19 or later).")
		}
	}

	// IPAMENI IPSec is configured from Reinitialize() to pull in devices
	// that may be added or removed at runtime.
	if option.Config.EnableIPSec &&
		!option.Config.TunnelingEnabled() &&
		len(option.Config.EncryptInterface) == 0 &&
		option.Config.IPAM != ipamOption.IPAMENI {
		link, err := linuxdatapath.NodeDeviceNameWithDefaultRoute()
		if err != nil {
			log.WithError(err).Fatal("Ipsec default interface lookup failed, consider \"encrypt-interface\" to manually configure interface.")
		}
		option.Config.EncryptInterface = append(option.Config.EncryptInterface, link)
	}

	if option.Config.TunnelingEnabled() && option.Config.EnableAutoDirectRouting {
		log.Fatalf("%s cannot be used with tunneling. Packets must be routed through the tunnel device.", option.EnableAutoDirectRoutingName)
	}

	initClockSourceOption()
	initSockmapOption()

	if option.Config.EnableSRv6 {
		if !option.Config.EnableIPv6 {
			log.Fatalf("SRv6 requires IPv6.")
		}
		if !probes.NewProbeManager().GetMapTypes().HaveLruHashMapType {
			log.Fatalf("SRv6 requires support for BPF LRU maps (Linux 4.10 or later).")
		}
	}

	if option.Config.EnableHostFirewall {
		if option.Config.EnableIPSec {
			log.Fatal("IPSec cannot be used with the host firewall.")
		}
		if option.Config.EnableEndpointRoutes && !option.Config.EnableRemoteNodeIdentity {
			log.Fatalf("The host firewall requires remote-node identities (%s) when running with %s",
				option.EnableRemoteNodeIdentity, option.EnableEndpointRoutes)
		}
	}

	if option.Config.EnableBandwidthManager && option.Config.EnableIPSec {
		log.Warning("The bandwidth manager cannot be used with IPSec. Disabling the bandwidth manager.")
		option.Config.EnableBandwidthManager = false
	}

	if option.Config.EnableIPv6Masquerade && option.Config.EnableBPFMasquerade {
		log.Fatal("BPF masquerade is not supported for IPv6.")
	}

	// If there is one device specified, use it to derive better default
	// allocation prefixes
	node.InitDefaultPrefix(option.Config.DirectRoutingDevice)

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
			node.SetIPv4(ip)
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

	if option.Config.EnableBPFTProxy {
		if h := probes.NewProbeManager().GetHelpers("sched_act"); h != nil {
			if _, ok := h["bpf_sk_assign"]; !ok {
				option.Config.EnableBPFTProxy = false
				log.Info("Disabled support for BPF TProxy due to missing kernel support for socket assign (Linux 5.7 or later)")
			}
		}
	}

	if option.Config.LocalRouterIPv4 != "" || option.Config.LocalRouterIPv6 != "" {
		// TODO(weil0ng): add a proper check for ipam in PR# 15429.
		if option.Config.TunnelingEnabled() {
			log.Fatalf("Cannot specify %s or %s in tunnel mode.", option.LocalRouterIPv4, option.LocalRouterIPv6)
		}
		if !option.Config.EnableEndpointRoutes {
			log.Fatalf("Cannot specify %s or %s  without %s.", option.LocalRouterIPv4, option.LocalRouterIPv6, option.EnableEndpointRoutes)
		}
		if option.Config.EnableIPSec {
			log.Fatalf("Cannot specify %s or %s with %s.", option.LocalRouterIPv4, option.LocalRouterIPv6, option.EnableIPSecName)
		}
	}

	if option.Config.IPAM == ipamOption.IPAMAzure {
		option.Config.EgressMultiHomeIPRuleCompat = true
		log.WithFields(logrus.Fields{
			"URL": "https://github.com/cilium/cilium/issues/14705",
		}).Infof(
			"Auto-set %q to `true` because the Azure datapath has not been migrated over to a new scheme. "+
				"A future version of Cilium will support a newer Azure datapath. "+
				"Connectivity is not affected.",
			option.EgressMultiHomeIPRuleCompat,
		)
	}

	if option.Config.IPAM == ipamOption.IPAMClusterPoolV2 {
		if option.Config.TunnelingEnabled() {
			log.Fatalf("Cannot specify IPAM mode %s in tunnel mode.", ipamOption.IPAMClusterPoolV2)
		}
		if option.Config.EnableIPSec {
			log.Fatalf("Cannot specify IPAM mode %s with %s.", ipamOption.IPAMClusterPoolV2, option.EnableIPSecName)
		}
	}

	if option.Config.InstallNoConntrackIptRules {
		// InstallNoConntrackIptRules can only be enabled in direct
		// routing mode as in tunneling mode the encapsulated traffic is
		// already skipping netfilter conntrack.
		if option.Config.TunnelingEnabled() {
			log.Fatalf("%s requires the agent to run in direct routing mode.", option.InstallNoConntrackIptRules)
		}

		// Moreover InstallNoConntrackIptRules requires IPv4 support as
		// the native routing CIDR, used to select all pod traffic, can
		// only be an IPv4 CIDR at the moment.
		if !option.Config.EnableIPv4 {
			log.Fatalf("%s requires IPv4 support.", option.InstallNoConntrackIptRules)
		}
	}

	if option.Config.BGPAnnouncePodCIDR &&
		(option.Config.IPAM != ipamOption.IPAMClusterPool &&
			option.Config.IPAM != ipamOption.IPAMKubernetes) {
		log.Fatalf("BGP announcements for pod CIDRs is not supported with IPAM mode %q (only %q and %q are supported)",
			option.Config.IPAM, ipamOption.IPAMClusterPool, ipamOption.IPAMKubernetes)
	}

	// Ensure that the user does not turn on this mode unless it's for an IPAM
	// mode which support the bypass.
	if option.Config.BypassIPAvailabilityUponRestore {
		switch option.Config.IPAMMode() {
		case ipamOption.IPAMENI, ipamOption.IPAMAzure:
			log.Info(
				"Running with bypass of IP not available errors upon endpoint " +
					"restore. Be advised that this mode is intended to be " +
					"temporary to ease upgrades. Consider restarting the pods " +
					"which have IPs not from the pool.",
			)
		default:
			option.Config.BypassIPAvailabilityUponRestore = false
			log.Warnf(
				"Bypassing IP allocation upon endpoint restore (%q) is enabled with"+
					"unintended IPAM modes. This bypass is only intended "+
					"to work for CRD-based IPAM modes such as ENI. Disabling "+
					"bypass.",
				option.BypassIPAvailabilityUponRestore,
			)
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
		d.k8sWatcher.WaitForCacheSync(
			resources.K8sAPIGroupServiceV1Core,
			resources.K8sAPIGroupEndpointV1Core,
			resources.K8sAPIGroupEndpointSliceV1Discovery,
			resources.K8sAPIGroupEndpointSliceV1Beta1Discovery,
		)
		log := log.WithField(logfields.LogSubsys, "etcd")
		goopts.DialOption = []grpc.DialOption{
			grpc.WithContextDialer(k8s.CreateCustomDialer(&d.k8sWatcher.K8sSvcCache, log)),
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

func daemonModule(ctx context.Context, cleaner *daemonCleanup, shutdowner fx.Shutdowner) (*Daemon, error) {
	datapathConfig := linuxdatapath.DatapathConfiguration{
		HostDevice: defaults.HostDevice,
		ProcFs:     option.Config.ProcFs,
	}

	log.Info("Initializing daemon")

	option.Config.RunMonitorAgent = true

	if err := enableIPForwarding(); err != nil {
		return nil, fmt.Errorf("enabling IP forwarding via sysctl failed: %w", err)
	}

	iptablesManager := &iptables.IptablesManager{}
	iptablesManager.Init()

	var wgAgent *wireguard.Agent
	if option.Config.EnableWireguard {
		switch {
		case option.Config.EnableIPSec:
			return nil, fmt.Errorf("Wireguard (--%s) cannot be used with IPSec (--%s)",
				option.EnableWireguard, option.EnableIPSecName)
		case option.Config.EnableL7Proxy:
			return nil, fmt.Errorf("Wireguard (--%s) is not compatible with L7 proxy (--%s)",
				option.EnableWireguard, option.EnableL7Proxy)
		}

		var err error
		privateKeyPath := filepath.Join(option.Config.StateDir, wireguardTypes.PrivKeyFilename)
		wgAgent, err = wireguard.NewAgent(privateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wireguard: %w", err)
		}

		cleaner.cleanupFuncs.Add(func() {
			_ = wgAgent.Close()
		})
	} else {
		// Delete wireguard device from previous run (if such exists)
		link.DeleteByName(wireguardTypes.IfaceName)
	}

	if k8s.IsEnabled() {
		bootstrapStats.k8sInit.Start()
		if err := k8s.Init(option.Config); err != nil {
			return nil, fmt.Errorf("unable to initialize Kubernetes subsystem: %w", err)
		}
		bootstrapStats.k8sInit.End(true)
	}

	d, restoredEndpoints, err := NewDaemon(ctx, cleaner,
		WithDefaultEndpointManager(ctx, endpoint.CheckHealth),
		linuxdatapath.NewDatapath(datapathConfig, iptablesManager, wgAgent))
	if err != nil {
		return nil, fmt.Errorf("daemon creation failed: %w", err)
	}

	// This validation needs to be done outside of the agent until
	// datapath.NodeAddressing is used consistently across the code base.
	log.Info("Validating configured node address ranges")
	if err := node.ValidatePostInit(); err != nil {
		return nil, fmt.Errorf("postinit failed: %w", err)
	}

	bootstrapStats.enableConntrack.Start()
	log.Info("Starting connection tracking garbage collector")
	gc.Enable(option.Config.EnableIPv4, option.Config.EnableIPv6,
		restoredEndpoints.restored, d.endpointManager,
		d.datapath.LocalNodeAddressing())
	bootstrapStats.enableConntrack.End(true)

	bootstrapStats.k8sInit.Start()
	if k8s.IsEnabled() {
		// Wait only for certain caches, but not all!
		// (Check Daemon.InitK8sSubsystem() for more info)
		<-d.k8sCachesSynced
	}
	bootstrapStats.k8sInit.End(true)
	restoreComplete := d.initRestore(restoredEndpoints)
	if wgAgent != nil {
		if err := wgAgent.RestoreFinished(); err != nil {
			log.WithError(err).Error("Failed to set up wireguard peers")
		}
	}

	if d.endpointManager.HostEndpointExists() {
		d.endpointManager.InitHostEndpointLabels(d.ctx)
	} else {
		log.Info("Creating host endpoint")
		if err := d.endpointManager.AddHostEndpoint(
			d.ctx, d, d, d.ipcache, d.l7Proxy, d.identityAllocator,
			"Create host endpoint", nodeTypes.GetName(),
		); err != nil {
			return nil, fmt.Errorf("unable to create host endpoint: %w", err)
		}
	}

	if option.Config.EnableIPMasqAgent {
		ipmasqAgent, err := ipmasq.NewIPMasqAgent(option.Config.IPMasqAgentConfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create ipmasq agent: %w", err)
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

			if len(d.restoredCIDRs) > 0 {
				// Release restored CIDR identities after a grace period (default 10
				// minutes).  Any identities actually in use will still exist after
				// this.
				//
				// This grace period is needed when running on an external workload
				// where policy synchronization is not done via k8s. Also in k8s
				// case it is prudent to allow concurrent endpoint regenerations to
				// (re-)allocate the restored identities before we release them.
				time.Sleep(option.Config.IdentityRestoreGracePeriod)
				log.Debugf("Releasing reference counts for %d restored CIDR identities", len(d.restoredCIDRs))

				d.ipcache.ReleaseCIDRIdentitiesByCIDR(d.restoredCIDRs)
				// release the memory held by restored CIDRs
				d.restoredCIDRs = nil
			}
		}()
		d.endpointManager.Subscribe(d)
		// Add the endpoint manager unsubscribe as the last step in cleanup
		defer cleaner.cleanupFuncs.Add(func() { d.endpointManager.Unsubscribe(d) })
	}

	// Migrating the ENI datapath must happen before the API is served to
	// prevent endpoints from being created. It also must be before the health
	// initialization logic which creates the health endpoint, for the same
	// reasons as the API being served. We want to ensure that this migration
	// logic runs before any endpoint creates.
	if option.Config.IPAM == ipamOption.IPAMENI {
		migrated, failed := linuxrouting.NewMigrator(
			&eni.InterfaceDB{},
		).MigrateENIDatapath(option.Config.EgressMultiHomeIPRuleCompat)
		switch {
		case failed == -1:
			// No need to handle this case specifically because it is handled
			// in the call already.
		case migrated >= 0 && failed > 0:
			log.Errorf("Failed to migrate ENI datapath. "+
				"%d endpoints were successfully migrated and %d failed to migrate completely. "+
				"The original datapath is still in-place, however it is recommended to retry the migration.",
				migrated, failed)

		case migrated >= 0 && failed == 0:
			log.Infof("Migration of ENI datapath successful, %d endpoints were migrated and none failed.",
				migrated)
		}
	}

	bootstrapStats.healthCheck.Start()
	if option.Config.EnableHealthChecking {
		d.initHealth(cleaner)
	}
	bootstrapStats.healthCheck.End(true)

	d.startStatusCollector(cleaner)

	go func(errs <-chan error) {
		err := <-errs
		if err != nil {
			log.WithError(err).Error("Cannot start metrics server")
			shutdowner.Shutdown()
		}
	}(initMetrics())

	d.startAgentHealthHTTPService()
	if option.Config.KubeProxyReplacementHealthzBindAddr != "" {
		if option.Config.KubeProxyReplacement != option.KubeProxyReplacementDisabled {
			d.startKubeProxyHealthzHTTPService(fmt.Sprintf("%s", option.Config.KubeProxyReplacementHealthzBindAddr))
		}
	}

	bootstrapStats.initAPI.Start()
	srv := server.NewServer(d.instantiateAPI())
	srv.EnabledListeners = []string{"unix"}
	srv.SocketPath = option.Config.SocketPath
	srv.ReadTimeout = apiTimeout
	srv.WriteTimeout = apiTimeout
	cleaner.cleanupFuncs.Add(func() { srv.Shutdown() })

	srv.ConfigureAPI()
	bootstrapStats.initAPI.End(true)

	err = d.SendNotification(monitorAPI.StartMessage(time.Now()))
	if err != nil {
		log.WithError(err).Warn("Failed to send agent start monitor message")
	}

	if !d.datapath.Node().NodeNeighDiscoveryEnabled() {
		// Remove all non-GC'ed neighbor entries that might have previously set
		// by a Cilium instance.
		d.datapath.Node().NodeCleanNeighbors(false)
	} else {
		// If we came from an agent upgrade, migrate entries.
		d.datapath.Node().NodeCleanNeighbors(true)
		// Start periodical refresh of the neighbor table from the agent if needed.
		if option.Config.ARPPingRefreshPeriod != 0 && !option.Config.ARPPingKernelManaged {
			d.nodeDiscovery.Manager.StartNeighborRefresh(d.datapath.Node())
		}
	}

	if option.Config.BGPControlPlaneEnabled() {
		switch option.Config.IPAM {
		case ipamOption.IPAMClusterPool:
		case ipamOption.IPAMClusterPoolV2:
		case ipamOption.IPAMKubernetes:
		default:
			log.Fatalf("BGP control plane cannot be utilized with IPAM mode: %v", option.Config.IPAM)
		}
		log.Info("Initializing BGP Control Plane")
		if err := d.instantiateBGPControlPlane(d.ctx); err != nil {
			return nil, fmt.Errorf("failed to initialize BGP control plane: %w", err)
		}
	}

	log.WithField("bootstrapTime", time.Since(bootstrapTimestamp)).
		Info("Daemon initialization completed")

	if option.Config.WriteCNIConfigurationWhenReady != "" {
		input, err := os.ReadFile(option.Config.ReadCNIConfiguration)
		if err != nil {
			return nil, fmt.Errorf("unable to read cni configuration file: %w", err)
		}

		if err = os.WriteFile(option.Config.WriteCNIConfigurationWhenReady, input, 0644); err != nil {
			return nil, fmt.Errorf("unable to write CNI configuration file to %s: %w",
				option.Config.WriteCNIConfigurationWhenReady,
				err)
		} else {
			log.Infof("Wrote CNI configuration file to %s", option.Config.WriteCNIConfigurationWhenReady)
		}
	}

	go func() {
		err := srv.Serve()
		if err != nil {
			log.WithError(err).Error("Error returned from non-returning Serve() call")
			shutdowner.Shutdown()
		}
	}()

	bootstrapStats.overall.End(true)
	bootstrapStats.updateMetrics()
	go d.launchHubble()

	err = option.Config.StoreInFile(option.Config.StateDir)
	if err != nil {
		log.WithError(err).Error("Unable to store Cilium's configuration")
	}

	err = option.StoreViperInFile(option.Config.StateDir)
	if err != nil {
		log.WithError(err).Error("Unable to store Viper's configuration")
	}

	return d, nil
}

func (d *Daemon) instantiateBGPControlPlane(ctx context.Context) error {
	// goBGP is currently the only supported RouterManager, if more are
	// implemented replace this hard-coding with a construction switch.
	rm := gobgp.NewBGPRouterManager()
	ctrl, err := bgpv1.NewController(d.ctx, rm)
	if err != nil {
		return fmt.Errorf("failed to instantiate BGP Control Plane: %v", err)
	}
	d.bgpControlPlaneController = ctrl
	return nil
}

func (d *Daemon) instantiateAPI() *restapi.CiliumAPIAPI {
	swaggerSpec, err := loads.Analyzed(server.SwaggerJSON, "")
	if err != nil {
		log.WithError(err).Fatal("Cannot load swagger spec")
	}

	log.Info("Initializing Cilium API")
	restAPI := restapi.NewCiliumAPIAPI(swaggerSpec)

	restAPI.Logger = log.Infof

	// /healthz/
	restAPI.DaemonGetHealthzHandler = NewGetHealthzHandler(d)

	// /cluster/nodes
	restAPI.DaemonGetClusterNodesHandler = NewGetClusterNodesHandler(d)

	// /config/
	restAPI.DaemonGetConfigHandler = NewGetConfigHandler(d)
	restAPI.DaemonPatchConfigHandler = NewPatchConfigHandler(d)

	if option.Config.DatapathMode != datapathOption.DatapathModeLBOnly {
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

		// /lrp/
		restAPI.ServiceGetLrpHandler = NewGetLrpHandler(d.redirectPolicyManager)
	}

	// /service/{id}/
	restAPI.ServiceGetServiceIDHandler = NewGetServiceIDHandler(d.svc)
	restAPI.ServiceDeleteServiceIDHandler = NewDeleteServiceIDHandler(d.svc)
	restAPI.ServicePutServiceIDHandler = NewPutServiceIDHandler(d.svc)

	// /service/
	restAPI.ServiceGetServiceHandler = NewGetServiceHandler(d.svc)

	// /recorder/{id}/
	restAPI.RecorderGetRecorderIDHandler = NewGetRecorderIDHandler(d.rec)
	restAPI.RecorderDeleteRecorderIDHandler = NewDeleteRecorderIDHandler(d.rec)
	restAPI.RecorderPutRecorderIDHandler = NewPutRecorderIDHandler(d.rec)

	// /recorder/
	restAPI.RecorderGetRecorderHandler = NewGetRecorderHandler(d.rec)

	// /recorder/masks
	restAPI.RecorderGetRecorderMasksHandler = NewGetRecorderMasksHandler(d.rec)

	// /prefilter/
	restAPI.PrefilterGetPrefilterHandler = NewGetPrefilterHandler(d)
	restAPI.PrefilterDeletePrefilterHandler = NewDeletePrefilterHandler(d)
	restAPI.PrefilterPatchPrefilterHandler = NewPatchPrefilterHandler(d)

	if option.Config.DatapathMode != datapathOption.DatapathModeLBOnly {
		// /ipam/{ip}/
		restAPI.IpamPostIpamHandler = NewPostIPAMHandler(d)
		restAPI.IpamPostIpamIPHandler = NewPostIPAMIPHandler(d)
		restAPI.IpamDeleteIpamIPHandler = NewDeleteIPAMIPHandler(d)
	}

	// /debuginfo
	restAPI.DaemonGetDebuginfoHandler = NewGetDebugInfoHandler(d)

	// /map
	restAPI.DaemonGetMapHandler = NewGetMapHandler(d)
	restAPI.DaemonGetMapNameHandler = NewGetMapNameHandler(d)

	// metrics
	restAPI.MetricsGetMetricsHandler = NewGetMetricsHandler(d)

	if option.Config.DatapathMode != datapathOption.DatapathModeLBOnly {
		// /fqdn/cache
		restAPI.PolicyGetFqdnCacheHandler = NewGetFqdnCacheHandler(d)
		restAPI.PolicyDeleteFqdnCacheHandler = NewDeleteFqdnCacheHandler(d)
		restAPI.PolicyGetFqdnCacheIDHandler = NewGetFqdnCacheIDHandler(d)
		restAPI.PolicyGetFqdnNamesHandler = NewGetFqdnNamesHandler(d)
	}

	// /ip/
	restAPI.PolicyGetIPHandler = NewGetIPHandler(d)

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
