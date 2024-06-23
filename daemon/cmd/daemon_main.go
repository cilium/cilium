// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	healthApi "github.com/cilium/cilium/api/v1/health/server"
	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/daemon/cmd/cni"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/auth"
	"github.com/cilium/cilium/pkg/aws/eni"
	"github.com/cilium/cilium/pkg/bgp/speaker"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cgroups"
	cgroup "github.com/cilium/cilium/pkg/cgroups/manager"
	"github.com/cilium/cilium/pkg/clustermesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/maps"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hubble/exporter/exporteroption"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/ipmasq"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/l2announcer"
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
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"
	"github.com/cilium/cilium/pkg/policy"
	policyDirectory "github.com/cilium/cilium/pkg/policy/directory"
	policyK8s "github.com/cilium/cilium/pkg/policy/k8s"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/recorder"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
	wireguard "github.com/cilium/cilium/pkg/wireguard/agent"
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
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, daemonSubsys)

	bootstrapTimestamp = time.Now()
	bootstrapStats     = bootstrapStatistics{}
)

func InitGlobalFlags(cmd *cobra.Command, vp *viper.Viper) {
	flags := cmd.Flags()

	// Validators
	option.Config.FixedIdentityMappingValidator = option.Validator(func(val string) (string, error) {
		vals := strings.Split(val, "=")
		if len(vals) != 2 {
			return "", fmt.Errorf(`invalid fixed identity: expecting "<numeric-identity>=<identity-name>" got %q`, val)
		}
		ni, err := identity.ParseNumericIdentity(vals[0])
		if err != nil {
			return "", fmt.Errorf(`invalid numeric identity %q: %w`, val, err)
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

	option.Config.BPFMapEventBuffersValidator = option.Validator(func(val string) (string, error) {
		vals := strings.Split(val, "=")
		if len(vals) != 2 {
			return "", fmt.Errorf(`invalid bpf map event config: expecting "<map_name>=<enabled>,<max_size>,<ttl>" got %q`, val)
		}
		_, err := option.ParseEventBufferTupleString(vals[1])
		if err != nil {
			return "", fmt.Errorf(`invalid bpf map event config: expecting "<map_name>=<enabled>,<max_size>,<ttl>" got %q`, val)
		}
		return "", nil
	})

	option.Config.FixedZoneMappingValidator = option.Validator(func(val string) (string, error) {
		vals := strings.Split(val, "=")
		if len(vals) != 2 {
			return "", fmt.Errorf(`invalid fixed zone: expecting "<zone-name>=<numeric-id>" got %q`, val)
		}
		lblStr := vals[0]
		if len(lblStr) == 0 {
			return "", fmt.Errorf(`invalid label: %q`, lblStr)
		}
		ni, err := strconv.Atoi(vals[1])
		if err != nil {
			return "", fmt.Errorf(`invalid numeric ID %q: %w`, vals[1], err)
		}
		if min, max := 1, math.MaxUint8; ni < min || ni >= max {
			return "", fmt.Errorf(`invalid numeric ID %q: valid numeric ID is between %d and %d`, vals[1], min, max)
		}
		return val, nil
	})

	// Env bindings
	flags.Int(option.AgentHealthPort, defaults.AgentHealthPort, "TCP port for agent health status API")
	option.BindEnv(vp, option.AgentHealthPort)

	flags.Int(option.ClusterHealthPort, defaults.ClusterHealthPort, "TCP port for cluster-wide network connectivity health API")
	option.BindEnv(vp, option.ClusterHealthPort)

	flags.StringSlice(option.AgentLabels, []string{}, "Additional labels to identify this agent")
	option.BindEnv(vp, option.AgentLabels)

	flags.Bool(option.AllowICMPFragNeeded, defaults.AllowICMPFragNeeded, "Allow ICMP Fragmentation Needed type packets for purposes like TCP Path MTU.")
	option.BindEnv(vp, option.AllowICMPFragNeeded)

	flags.String(option.AllowLocalhost, option.AllowLocalhostAuto, "Policy when to allow local stack to reach local endpoints { auto | always | policy }")
	option.BindEnv(vp, option.AllowLocalhost)

	flags.Bool(option.AnnotateK8sNode, defaults.AnnotateK8sNode, "Annotate Kubernetes node")
	option.BindEnv(vp, option.AnnotateK8sNode)

	flags.Duration(option.ARPPingRefreshPeriod, defaults.ARPBaseReachableTime, "Period for remote node ARP entry refresh (set 0 to disable)")
	option.BindEnv(vp, option.ARPPingRefreshPeriod)

	flags.Bool(option.EnableL2NeighDiscovery, true, "Enables L2 neighbor discovery used by kube-proxy-replacement and IPsec")
	option.BindEnv(vp, option.EnableL2NeighDiscovery)

	flags.Bool(option.AutoCreateCiliumNodeResource, defaults.AutoCreateCiliumNodeResource, "Automatically create CiliumNode resource for own node on startup")
	option.BindEnv(vp, option.AutoCreateCiliumNodeResource)

	flags.StringSlice(option.ExcludeNodeLabelPatterns, []string{}, "List of k8s node label regex patterns to be excluded from CiliumNode")
	option.BindEnv(vp, option.ExcludeNodeLabelPatterns)

	flags.String(option.BPFRoot, "", "Path to BPF filesystem")
	option.BindEnv(vp, option.BPFRoot)

	flags.Bool(option.EnableBPFClockProbe, false, "Enable BPF clock source probing for more efficient tick retrieval")
	option.BindEnv(vp, option.EnableBPFClockProbe)

	flags.String(option.CGroupRoot, "", "Path to Cgroup2 filesystem")
	option.BindEnv(vp, option.CGroupRoot)

	flags.StringSlice(option.CompilerFlags, []string{}, "Extra CFLAGS for BPF compilation")
	flags.MarkHidden(option.CompilerFlags)
	option.BindEnv(vp, option.CompilerFlags)

	flags.String(option.ConfigFile, "", `Configuration file (default "$HOME/ciliumd.yaml")`)
	option.BindEnv(vp, option.ConfigFile)

	flags.String(option.ConfigDir, "", `Configuration directory that contains a file for each option`)
	option.BindEnv(vp, option.ConfigDir)

	flags.Duration(option.ConntrackGCInterval, time.Duration(0), "Overwrite the connection-tracking garbage collection interval")
	option.BindEnv(vp, option.ConntrackGCInterval)

	flags.Duration(option.ConntrackGCMaxInterval, time.Duration(0), "Set the maximum interval for the connection-tracking garbage collection")
	option.BindEnv(vp, option.ConntrackGCMaxInterval)

	flags.BoolP(option.DebugArg, "D", false, "Enable debugging mode")
	option.BindEnv(vp, option.DebugArg)

	flags.StringSlice(option.DebugVerbose, []string{}, "List of enabled verbose debug groups")
	option.BindEnv(vp, option.DebugVerbose)

	flags.Bool(option.EnableRuntimeDeviceDetection, true, "Enable runtime device detection and datapath reconfiguration (experimental)")
	option.BindEnv(vp, option.EnableRuntimeDeviceDetection)
	flags.MarkDeprecated(option.EnableRuntimeDeviceDetection, "Runtime device detection and datapath reconfiguration is now the default and only mode of operation")

	flags.String(option.DatapathMode, defaults.DatapathMode,
		fmt.Sprintf("Datapath mode name (%s, %s, %s, %s)",
			datapathOption.DatapathModeVeth, datapathOption.DatapathModeNetkit,
			datapathOption.DatapathModeNetkitL2, datapathOption.DatapathModeLBOnly))
	option.BindEnv(vp, option.DatapathMode)

	flags.Bool(option.EnableEndpointRoutes, defaults.EnableEndpointRoutes, "Use per endpoint routes instead of routing via cilium_host")
	option.BindEnv(vp, option.EnableEndpointRoutes)

	flags.Bool(option.EnableHealthChecking, defaults.EnableHealthChecking, "Enable connectivity health checking")
	option.BindEnv(vp, option.EnableHealthChecking)

	flags.Bool(option.EnableHealthCheckNodePort, defaults.EnableHealthCheckNodePort, "Enables a healthcheck nodePort server for NodePort services with 'healthCheckNodePort' being set")
	option.BindEnv(vp, option.EnableHealthCheckNodePort)

	flags.Bool(option.EnableHealthCheckLoadBalancerIP, defaults.EnableHealthCheckLoadBalancerIP, "Enable access of the healthcheck nodePort on the LoadBalancerIP. Needs --enable-health-check-nodeport to be enabled")
	option.BindEnv(vp, option.EnableHealthCheckLoadBalancerIP)

	flags.Bool(option.EnableEndpointHealthChecking, defaults.EnableEndpointHealthChecking, "Enable connectivity health checking between virtual endpoints")
	option.BindEnv(vp, option.EnableEndpointHealthChecking)

	flags.Bool(option.EnableLocalNodeRoute, defaults.EnableLocalNodeRoute, "Enable installation of the route which points the allocation prefix of the local node")
	option.BindEnv(vp, option.EnableLocalNodeRoute)

	flags.Bool(option.EnableIPv4Name, defaults.EnableIPv4, "Enable IPv4 support")
	option.BindEnv(vp, option.EnableIPv4Name)

	flags.Bool(option.EnableIPv6Name, defaults.EnableIPv6, "Enable IPv6 support")
	option.BindEnv(vp, option.EnableIPv6Name)

	flags.Bool(option.EnableNat46X64Gateway, false, "Enable NAT46 and NAT64 gateway")
	option.BindEnv(vp, option.EnableNat46X64Gateway)

	flags.Bool(option.EnableIPIPTermination, false, "Enable plain IPIP/IP6IP6 termination")
	option.BindEnv(vp, option.EnableIPIPTermination)

	flags.Bool(option.EnableIPv6NDPName, defaults.EnableIPv6NDP, "Enable IPv6 NDP support")
	option.BindEnv(vp, option.EnableIPv6NDPName)

	flags.Bool(option.EnableSRv6, defaults.EnableSRv6, "Enable SRv6 support (beta)")
	flags.MarkHidden(option.EnableSRv6)
	option.BindEnv(vp, option.EnableSRv6)

	flags.String(option.SRv6EncapModeName, defaults.SRv6EncapMode, "Encapsulation mode for SRv6 (\"srh\" or \"reduced\")")
	flags.MarkHidden(option.SRv6EncapModeName)
	option.BindEnv(vp, option.SRv6EncapModeName)

	flags.Bool(option.EnableSCTPName, defaults.EnableSCTP, "Enable SCTP support (beta)")
	option.BindEnv(vp, option.EnableSCTPName)

	flags.String(option.IPv6MCastDevice, "", "Device that joins a Solicited-Node multicast group for IPv6")
	option.BindEnv(vp, option.IPv6MCastDevice)

	flags.String(option.EncryptInterface, "", "Transparent encryption interface")
	option.BindEnv(vp, option.EncryptInterface)

	flags.Bool(option.EncryptNode, defaults.EncryptNode, "Enables encrypting traffic from non-Cilium pods and host networking (only supported with WireGuard, beta)")
	option.BindEnv(vp, option.EncryptNode)

	flags.StringSlice(option.IPv4PodSubnets, []string{}, "List of IPv4 pod subnets to preconfigure for encryption")
	option.BindEnv(vp, option.IPv4PodSubnets)

	flags.StringSlice(option.IPv6PodSubnets, []string{}, "List of IPv6 pod subnets to preconfigure for encryption")
	option.BindEnv(vp, option.IPv6PodSubnets)

	flags.Var(option.NewNamedMapOptions(option.IPAMMultiPoolPreAllocation, &option.Config.IPAMMultiPoolPreAllocation, nil),
		option.IPAMMultiPoolPreAllocation,
		fmt.Sprintf("Defines the minimum number of IPs a node should pre-allocate from each pool (default %s=8)", defaults.IPAMDefaultIPPool))
	vp.SetDefault(option.IPAMMultiPoolPreAllocation, "")
	option.BindEnv(vp, option.IPAMMultiPoolPreAllocation)

	flags.String(option.IPAMDefaultIPPool, defaults.IPAMDefaultIPPool, "Name of the default IP Pool when using multi-pool")
	vp.SetDefault(option.IPAMDefaultIPPool, defaults.IPAMDefaultIPPool)
	option.BindEnv(vp, option.IPAMDefaultIPPool)

	flags.StringSlice(option.ExcludeLocalAddress, []string{}, "Exclude CIDR from being recognized as local address")
	option.BindEnv(vp, option.ExcludeLocalAddress)

	flags.Bool(option.DisableCiliumEndpointCRDName, false, "Disable use of CiliumEndpoint CRD")
	option.BindEnv(vp, option.DisableCiliumEndpointCRDName)

	flags.StringSlice(option.MasqueradeInterfaces, []string{}, "Limit iptables-based egress masquerading to interface selector")
	option.BindEnv(vp, option.MasqueradeInterfaces)

	flags.Bool(option.BPFSocketLBHostnsOnly, false, "Skip socket LB for services when inside a pod namespace, in favor of service LB at the pod interface. Socket LB is still used when in the host namespace. Required by service mesh (e.g., Istio, Linkerd).")
	option.BindEnv(vp, option.BPFSocketLBHostnsOnly)

	flags.Bool(option.EnableSocketLB, false, "Enable socket-based LB for E/W traffic")
	option.BindEnv(vp, option.EnableSocketLB)

	flags.Bool(option.EnableSocketLBPodConnectionTermination, true, "Enable terminating connections to deleted service backends when socket-LB is enabled")
	flags.MarkHidden(option.EnableSocketLBPodConnectionTermination)
	option.BindEnv(vp, option.EnableSocketLBPodConnectionTermination)

	flags.Bool(option.EnableSocketLBTracing, true, "Enable tracing for socket-based LB")
	option.BindEnv(vp, option.EnableSocketLBTracing)

	flags.Bool(option.EnableAutoDirectRoutingName, defaults.EnableAutoDirectRouting, "Enable automatic L2 routing between nodes")
	option.BindEnv(vp, option.EnableAutoDirectRoutingName)

	flags.Bool(option.DirectRoutingSkipUnreachableName, defaults.EnableDirectRoutingSkipUnreachable, "Enable skipping L2 routes between nodes on different subnets")
	option.BindEnv(vp, option.DirectRoutingSkipUnreachableName)

	flags.Bool(option.EnableBPFTProxy, defaults.EnableBPFTProxy, "Enable BPF-based proxy redirection, if support available")
	option.BindEnv(vp, option.EnableBPFTProxy)

	flags.Bool(option.EnableHostLegacyRouting, defaults.EnableHostLegacyRouting, "Enable the legacy host forwarding model which does not bypass upper stack in host namespace")
	option.BindEnv(vp, option.EnableHostLegacyRouting)

	flags.Bool(option.EnableXTSocketFallbackName, defaults.EnableXTSocketFallback, "Enable fallback for missing xt_socket module")
	option.BindEnv(vp, option.EnableXTSocketFallbackName)

	flags.String(option.EnablePolicy, option.DefaultEnforcement, "Enable policy enforcement")
	option.BindEnv(vp, option.EnablePolicy)

	flags.Bool(option.EnableExternalIPs, false, fmt.Sprintf("Enable k8s service externalIPs feature (requires enabling %s)", option.EnableNodePort))
	option.BindEnv(vp, option.EnableExternalIPs)

	flags.Bool(option.EnableL7Proxy, defaults.EnableL7Proxy, "Enable L7 proxy for L7 policy enforcement")
	option.BindEnv(vp, option.EnableL7Proxy)

	flags.Bool(option.BPFEventsDropEnabled, defaults.BPFEventsDropEnabled, "Expose 'drop' events for Cilium monitor and/or Hubble")
	option.BindEnv(vp, option.BPFEventsDropEnabled)

	flags.Bool(option.BPFEventsPolicyVerdictEnabled, defaults.BPFEventsPolicyVerdictEnabled, "Expose 'policy verdict' events for Cilium monitor and/or Hubble")
	option.BindEnv(vp, option.BPFEventsPolicyVerdictEnabled)

	flags.Bool(option.BPFEventsTraceEnabled, defaults.BPFEventsTraceEnabled, "Expose 'trace' events for Cilium monitor and/or Hubble")
	option.BindEnv(vp, option.BPFEventsTraceEnabled)

	flags.Bool(option.EnableTracing, false, "Enable tracing while determining policy (debugging)")
	option.BindEnv(vp, option.EnableTracing)

	flags.Bool(option.EnableUnreachableRoutes, false, "Add unreachable routes on pod deletion")
	option.BindEnv(vp, option.EnableUnreachableRoutes)

	flags.Bool(option.EnableWellKnownIdentities, defaults.EnableWellKnownIdentities, "Enable well-known identities for known Kubernetes components")
	option.BindEnv(vp, option.EnableWellKnownIdentities)

	flags.Bool(option.EnableIPSecName, defaults.EnableIPSec, "Enable IPsec support")
	option.BindEnv(vp, option.EnableIPSecName)

	flags.String(option.IPSecKeyFileName, "", "Path to IPsec key file")
	option.BindEnv(vp, option.IPSecKeyFileName)

	flags.Duration(option.IPsecKeyRotationDuration, defaults.IPsecKeyRotationDuration, "Maximum duration of the IPsec key rotation. The previous key will be removed after that delay.")
	option.BindEnv(vp, option.IPsecKeyRotationDuration)

	flags.Bool(option.EnableIPsecKeyWatcher, defaults.EnableIPsecKeyWatcher, "Enable watcher for IPsec key. If disabled, a restart of the agent will be necessary on key rotations.")
	option.BindEnv(vp, option.EnableIPsecKeyWatcher)

	flags.Bool(option.EnableIPSecXfrmStateCaching, defaults.EnableIPSecXfrmStateCaching, "Enable XfrmState cache for IPSec. Significantly reduces CPU usage in large clusters.")
	flags.MarkHidden(option.EnableIPSecXfrmStateCaching)
	option.BindEnv(vp, option.EnableIPSecXfrmStateCaching)

	flags.Bool(option.EnableIPSecEncryptedOverlay, defaults.EnableIPSecEncryptedOverlay, "Enable IPsec encrypted overlay. If enabled tunnel traffic will be encrypted before leaving the host. Requires ipsec and tunnel mode vxlan to be enabled.")
	option.BindEnv(vp, option.EnableIPSecEncryptedOverlay)

	flags.Bool(option.EnableWireguard, false, "Enable WireGuard")
	option.BindEnv(vp, option.EnableWireguard)

	flags.Bool(option.EnableL2Announcements, false, "Enable L2 announcements")
	option.BindEnv(vp, option.EnableL2Announcements)

	flags.Duration(option.L2AnnouncerLeaseDuration, 15*time.Second, "Duration of inactivity after which a new leader is selected")
	option.BindEnv(vp, option.L2AnnouncerLeaseDuration)

	flags.Duration(option.L2AnnouncerRenewDeadline, 5*time.Second, "Interval at which the leader renews a lease")
	option.BindEnv(vp, option.L2AnnouncerRenewDeadline)

	flags.Duration(option.L2AnnouncerRetryPeriod, 2*time.Second, "Timeout after a renew failure, before the next retry")
	option.BindEnv(vp, option.L2AnnouncerRetryPeriod)

	flags.Bool(option.EnableWireguardUserspaceFallback, false, "Enable fallback to the WireGuard userspace implementation")
	flags.MarkDeprecated(option.EnableWireguardUserspaceFallback, "WireGuard userspace fallback is deprecated")
	option.BindEnv(vp, option.EnableWireguardUserspaceFallback)

	flags.Duration(option.WireguardPersistentKeepalive, 0, "The Wireguard keepalive interval as a Go duration string")
	option.BindEnv(vp, option.WireguardPersistentKeepalive)

	flags.String(option.NodeEncryptionOptOutLabels, defaults.NodeEncryptionOptOutLabels, "Label selector for nodes which will opt-out of node-to-node encryption")
	option.BindEnv(vp, option.NodeEncryptionOptOutLabels)

	flags.Bool(option.EnableEncryptionStrictMode, false, "Enable encryption strict mode")
	option.BindEnv(vp, option.EnableEncryptionStrictMode)

	flags.String(option.EncryptionStrictModeCIDR, "", "In strict-mode encryption, all unencrypted traffic coming from this CIDR and going to this same CIDR will be dropped")
	option.BindEnv(vp, option.EncryptionStrictModeCIDR)

	flags.Bool(option.EncryptionStrictModeAllowRemoteNodeIdentities, false, "Allows unencrypted traffic from pods to remote node identities within the strict mode CIDR. This is required when tunneling is used or direct routing is used and the node CIDR and pod CIDR overlap.")
	option.BindEnv(vp, option.EncryptionStrictModeAllowRemoteNodeIdentities)

	flags.Var(option.NewNamedMapOptions(option.FixedIdentityMapping, &option.Config.FixedIdentityMapping, option.Config.FixedIdentityMappingValidator),
		option.FixedIdentityMapping, "Key-value for the fixed identity mapping which allows to use reserved label for fixed identities, e.g. 128=kv-store,129=kube-dns")
	option.BindEnv(vp, option.FixedIdentityMapping)

	flags.Duration(option.IdentityChangeGracePeriod, defaults.IdentityChangeGracePeriod, "Time to wait before using new identity on endpoint identity change")
	option.BindEnv(vp, option.IdentityChangeGracePeriod)

	flags.Duration(option.IdentityRestoreGracePeriod, defaults.IdentityRestoreGracePeriodK8s, "Time to wait before releasing unused restored CIDR identities during agent restart")
	option.BindEnv(vp, option.IdentityRestoreGracePeriod)

	flags.String(option.IdentityAllocationMode, option.IdentityAllocationModeKVstore, "Method to use for identity allocation")
	option.BindEnv(vp, option.IdentityAllocationMode)

	flags.String(option.IPAM, ipamOption.IPAMClusterPool, "Backend to use for IPAM")
	option.BindEnv(vp, option.IPAM)

	flags.String(option.IPv4Range, AutoCIDR, "Per-node IPv4 endpoint prefix, e.g. 10.16.0.0/16")
	option.BindEnv(vp, option.IPv4Range)

	flags.String(option.IPv6Range, AutoCIDR, "Per-node IPv6 endpoint prefix, e.g. fd02:1:1::/96")
	option.BindEnv(vp, option.IPv6Range)

	flags.String(option.IPv6ClusterAllocCIDRName, defaults.IPv6ClusterAllocCIDR, "IPv6 /64 CIDR used to allocate per node endpoint /96 CIDR")
	option.BindEnv(vp, option.IPv6ClusterAllocCIDRName)

	flags.String(option.IPv4ServiceRange, AutoCIDR, "Kubernetes IPv4 services CIDR if not inside cluster prefix")
	option.BindEnv(vp, option.IPv4ServiceRange)

	flags.String(option.IPv6ServiceRange, AutoCIDR, "Kubernetes IPv6 services CIDR if not inside cluster prefix")
	option.BindEnv(vp, option.IPv6ServiceRange)

	flags.String(option.K8sNamespaceName, "", "Name of the Kubernetes namespace in which Cilium is deployed in")
	option.BindEnv(vp, option.K8sNamespaceName)

	flags.String(option.AgentNotReadyNodeTaintKeyName, defaults.AgentNotReadyNodeTaint, "Key of the taint indicating that Cilium is not ready on the node")
	option.BindEnv(vp, option.AgentNotReadyNodeTaintKeyName)

	flags.Bool(option.JoinClusterName, false, "Join a Cilium cluster via kvstore registration")
	option.BindEnv(vp, option.JoinClusterName)

	flags.Bool(option.K8sRequireIPv4PodCIDRName, false, "Require IPv4 PodCIDR to be specified in node resource")
	option.BindEnv(vp, option.K8sRequireIPv4PodCIDRName)

	flags.Bool(option.K8sRequireIPv6PodCIDRName, false, "Require IPv6 PodCIDR to be specified in node resource")
	option.BindEnv(vp, option.K8sRequireIPv6PodCIDRName)

	flags.Uint(option.K8sServiceCacheSize, defaults.K8sServiceCacheSize, "Cilium service cache size for kubernetes")
	option.BindEnv(vp, option.K8sServiceCacheSize)
	flags.MarkHidden(option.K8sServiceCacheSize)

	flags.String(option.K8sWatcherEndpointSelector, defaults.K8sWatcherEndpointSelector, "K8s endpoint watcher will watch for these k8s endpoints")
	option.BindEnv(vp, option.K8sWatcherEndpointSelector)

	flags.Bool(option.KeepConfig, false, "When restoring state, keeps containers' configuration in place")
	option.BindEnv(vp, option.KeepConfig)

	flags.String(option.KVStore, "", "Key-value store type")
	option.BindEnv(vp, option.KVStore)

	flags.Duration(option.KVstoreLeaseTTL, defaults.KVstoreLeaseTTL, "Time-to-live for the KVstore lease.")
	flags.MarkHidden(option.KVstoreLeaseTTL)
	option.BindEnv(vp, option.KVstoreLeaseTTL)

	flags.Uint(option.KVstoreMaxConsecutiveQuorumErrorsName, defaults.KVstoreMaxConsecutiveQuorumErrors, "Max acceptable kvstore consecutive quorum errors before the agent assumes permanent failure")
	option.BindEnv(vp, option.KVstoreMaxConsecutiveQuorumErrorsName)

	flags.Duration(option.KVstorePeriodicSync, defaults.KVstorePeriodicSync, "Periodic KVstore synchronization interval")
	option.BindEnv(vp, option.KVstorePeriodicSync)

	flags.Duration(option.KVstoreConnectivityTimeout, defaults.KVstoreConnectivityTimeout, "Time after which an incomplete kvstore operation  is considered failed")
	option.BindEnv(vp, option.KVstoreConnectivityTimeout)

	flags.Var(option.NewNamedMapOptions(option.KVStoreOpt, &option.Config.KVStoreOpt, nil),
		option.KVStoreOpt, "Key-value store options e.g. etcd.address=127.0.0.1:4001")
	option.BindEnv(vp, option.KVStoreOpt)

	flags.Duration(option.K8sSyncTimeoutName, defaults.K8sSyncTimeout, "Timeout after last K8s event for synchronizing k8s resources before exiting")
	flags.MarkHidden(option.K8sSyncTimeoutName)
	option.BindEnv(vp, option.K8sSyncTimeoutName)

	flags.Duration(option.AllocatorListTimeoutName, defaults.AllocatorListTimeout, "Timeout for listing allocator state before exiting")
	option.BindEnv(vp, option.AllocatorListTimeoutName)

	flags.String(option.LabelPrefixFile, "", "Valid label prefixes file path")
	option.BindEnv(vp, option.LabelPrefixFile)

	flags.StringSlice(option.Labels, []string{}, "List of label prefixes used to determine identity of an endpoint")
	option.BindEnv(vp, option.Labels)

	flags.String(option.KubeProxyReplacement, option.KubeProxyReplacementFalse, fmt.Sprintf(
		"Enable only selected features (will panic if any selected feature cannot be enabled) (%q), "+
			"or enable all features (will panic if any feature cannot be enabled) (%q)",
		option.KubeProxyReplacementFalse, option.KubeProxyReplacementTrue))
	option.BindEnv(vp, option.KubeProxyReplacement)

	flags.String(option.KubeProxyReplacementHealthzBindAddr, defaults.KubeProxyReplacementHealthzBindAddr, "The IP address with port for kube-proxy replacement health check server to serve on (set to '0.0.0.0:10256' for all IPv4 interfaces and '[::]:10256' for all IPv6 interfaces). Set empty to disable.")
	option.BindEnv(vp, option.KubeProxyReplacementHealthzBindAddr)

	flags.Bool(option.EnableHostPort, false, fmt.Sprintf("Enable k8s hostPort mapping feature (requires enabling %s)", option.EnableNodePort))
	option.BindEnv(vp, option.EnableHostPort)

	flags.Bool(option.EnableNodePort, false, "Enable NodePort type services by Cilium")
	option.BindEnv(vp, option.EnableNodePort)

	flags.Bool(option.EnableSVCSourceRangeCheck, true, "Enable check of service source ranges (currently, only for LoadBalancer)")
	option.BindEnv(vp, option.EnableSVCSourceRangeCheck)

	flags.String(option.AddressScopeMax, fmt.Sprintf("%d", defaults.AddressScopeMax), "Maximum local address scope for ipcache to consider host addresses")
	flags.MarkHidden(option.AddressScopeMax)
	option.BindEnv(vp, option.AddressScopeMax)

	flags.Bool(option.EnableRecorder, false, "Enable BPF datapath pcap recorder")
	option.BindEnv(vp, option.EnableRecorder)

	flags.Bool(option.EnableLocalRedirectPolicy, false, "Enable Local Redirect Policy")
	option.BindEnv(vp, option.EnableLocalRedirectPolicy)

	flags.Bool(option.EnableMKE, false, "Enable BPF kube-proxy replacement for MKE environments")
	flags.MarkHidden(option.EnableMKE)
	option.BindEnv(vp, option.EnableMKE)

	flags.String(option.CgroupPathMKE, "", "Cgroup v1 net_cls mount path for MKE environments")
	flags.MarkHidden(option.CgroupPathMKE)
	option.BindEnv(vp, option.CgroupPathMKE)

	flags.String(option.NodePortMode, option.NodePortModeSNAT, "BPF NodePort mode (\"snat\", \"dsr\", \"hybrid\")")
	flags.MarkHidden(option.NodePortMode)
	option.BindEnv(vp, option.NodePortMode)

	flags.String(option.NodePortAlg, option.NodePortAlgRandom, "BPF load balancing algorithm (\"random\", \"maglev\")")
	flags.MarkHidden(option.NodePortAlg)
	option.BindEnv(vp, option.NodePortAlg)

	flags.String(option.NodePortAcceleration, option.NodePortAccelerationDisabled, fmt.Sprintf(
		"BPF NodePort acceleration via XDP (\"%s\", \"%s\")",
		option.NodePortAccelerationNative, option.NodePortAccelerationDisabled))
	flags.MarkHidden(option.NodePortAcceleration)
	option.BindEnv(vp, option.NodePortAcceleration)

	flags.String(option.LoadBalancerMode, option.NodePortModeSNAT, "BPF load balancing mode (\"snat\", \"dsr\", \"hybrid\")")
	option.BindEnv(vp, option.LoadBalancerMode)

	flags.String(option.LoadBalancerAlg, option.NodePortAlgRandom, "BPF load balancing algorithm (\"random\", \"maglev\")")
	option.BindEnv(vp, option.LoadBalancerAlg)

	flags.String(option.LoadBalancerDSRDispatch, option.DSRDispatchOption, "BPF load balancing DSR dispatch method (\"opt\", \"ipip\", \"geneve\")")
	option.BindEnv(vp, option.LoadBalancerDSRDispatch)

	flags.String(option.LoadBalancerDSRL4Xlate, option.DSRL4XlateFrontend, "BPF load balancing DSR L4 DNAT method for IPIP (\"frontend\", \"backend\")")
	option.BindEnv(vp, option.LoadBalancerDSRL4Xlate)

	flags.String(option.LoadBalancerRSSv4CIDR, "", "BPF load balancing RSS outer source IPv4 CIDR prefix for IPIP")
	option.BindEnv(vp, option.LoadBalancerRSSv4CIDR)

	flags.String(option.LoadBalancerRSSv6CIDR, "", "BPF load balancing RSS outer source IPv6 CIDR prefix for IPIP")
	option.BindEnv(vp, option.LoadBalancerRSSv6CIDR)

	flags.Bool(option.LoadBalancerExternalControlPlane, false, "BPF load balancer uses an externally-provided control plane")
	option.BindEnv(vp, option.LoadBalancerExternalControlPlane)

	flags.String(option.LoadBalancerAcceleration, option.NodePortAccelerationDisabled, fmt.Sprintf(
		"BPF load balancing acceleration via XDP (\"%s\", \"%s\")",
		option.NodePortAccelerationNative, option.NodePortAccelerationDisabled))
	option.BindEnv(vp, option.LoadBalancerAcceleration)

	flags.Uint(option.MaglevTableSize, maglev.DefaultTableSize, "Maglev per service backend table size (parameter M)")
	option.BindEnv(vp, option.MaglevTableSize)

	flags.String(option.MaglevHashSeed, maglev.DefaultHashSeed, "Maglev cluster-wide hash seed (base64 encoded)")
	option.BindEnv(vp, option.MaglevHashSeed)

	flags.Bool(option.EnableAutoProtectNodePortRange, true,
		"Append NodePort range to net.ipv4.ip_local_reserved_ports if it overlaps "+
			"with ephemeral port range (net.ipv4.ip_local_port_range)")
	option.BindEnv(vp, option.EnableAutoProtectNodePortRange)

	flags.StringSlice(option.NodePortRange, []string{fmt.Sprintf("%d", option.NodePortMinDefault), fmt.Sprintf("%d", option.NodePortMaxDefault)}, "Set the min/max NodePort port range")
	option.BindEnv(vp, option.NodePortRange)

	flags.Bool(option.NodePortBindProtection, true, "Reject application bind(2) requests to service ports in the NodePort range")
	option.BindEnv(vp, option.NodePortBindProtection)

	flags.Bool(option.EnableSessionAffinity, false, "Enable support for service session affinity")
	option.BindEnv(vp, option.EnableSessionAffinity)

	flags.Bool(option.EnableIdentityMark, true, "Enable setting identity mark for local traffic")
	option.BindEnv(vp, option.EnableIdentityMark)

	flags.Bool(option.EnableHighScaleIPcache, defaults.EnableHighScaleIPcache, "Enable the high scale mode for ipcache")
	option.BindEnv(vp, option.EnableHighScaleIPcache)

	flags.Bool(option.EnableHostFirewall, false, "Enable host network policies")
	option.BindEnv(vp, option.EnableHostFirewall)

	flags.String(option.IPv4NativeRoutingCIDR, "", "Allows to explicitly specify the IPv4 CIDR for native routing. "+
		"When specified, Cilium assumes networking for this CIDR is preconfigured and hands traffic destined for that range to the Linux network stack without applying any SNAT. "+
		"Generally speaking, specifying a native routing CIDR implies that Cilium can depend on the underlying networking stack to route packets to their destination. "+
		"To offer a concrete example, if Cilium is configured to use direct routing and the Kubernetes CIDR is included in the native routing CIDR, the user must configure the routes to reach pods, either manually or by setting the auto-direct-node-routes flag.")
	option.BindEnv(vp, option.IPv4NativeRoutingCIDR)

	flags.String(option.IPv6NativeRoutingCIDR, "", "Allows to explicitly specify the IPv6 CIDR for native routing. "+
		"When specified, Cilium assumes networking for this CIDR is preconfigured and hands traffic destined for that range to the Linux network stack without applying any SNAT. "+
		"Generally speaking, specifying a native routing CIDR implies that Cilium can depend on the underlying networking stack to route packets to their destination. "+
		"To offer a concrete example, if Cilium is configured to use direct routing and the Kubernetes CIDR is included in the native routing CIDR, the user must configure the routes to reach pods, either manually or by setting the auto-direct-node-routes flag.")
	option.BindEnv(vp, option.IPv6NativeRoutingCIDR)

	flags.String(option.LibDir, defaults.LibraryPath, "Directory path to store runtime build environment")
	option.BindEnv(vp, option.LibDir)

	flags.StringSlice(option.LogDriver, []string{}, "Logging endpoints to use for example syslog")
	option.BindEnv(vp, option.LogDriver)

	flags.Var(option.NewNamedMapOptions(option.LogOpt, &option.Config.LogOpt, nil),
		option.LogOpt, `Log driver options for cilium-agent, `+
			`configmap example for syslog driver: {"syslog.level":"info","syslog.facility":"local5","syslog.tag":"cilium-agent"}`)
	option.BindEnv(vp, option.LogOpt)

	flags.Bool(option.LogSystemLoadConfigName, false, "Enable periodic logging of system load")
	option.BindEnv(vp, option.LogSystemLoadConfigName)

	flags.String(option.LoopbackIPv4, defaults.LoopbackIPv4, "IPv4 address for service loopback SNAT")
	option.BindEnv(vp, option.LoopbackIPv4)

	flags.Bool(option.EnableIPv4Masquerade, true, "Masquerade IPv4 traffic from endpoints leaving the host")
	option.BindEnv(vp, option.EnableIPv4Masquerade)

	flags.Bool(option.EnableIPv6Masquerade, true, "Masquerade IPv6 traffic from endpoints leaving the host")
	option.BindEnv(vp, option.EnableIPv6Masquerade)

	flags.Bool(option.EnableBPFMasquerade, false, "Masquerade packets from endpoints leaving the host with BPF instead of iptables")
	option.BindEnv(vp, option.EnableBPFMasquerade)

	flags.Bool(option.EnableMasqueradeRouteSource, false, "Masquerade packets to the source IP provided from the routing layer rather than interface address")
	option.BindEnv(vp, option.EnableMasqueradeRouteSource)

	flags.Bool(option.EnableIPMasqAgent, false, "Enable BPF ip-masq-agent")
	option.BindEnv(vp, option.EnableIPMasqAgent)

	flags.Bool(option.EnableIPv4EgressGateway, false, "Enable egress gateway for IPv4")
	option.BindEnv(vp, option.EnableIPv4EgressGateway)

	flags.Bool(option.EnableEnvoyConfig, false, "Enable Envoy Config CRDs")
	option.BindEnv(vp, option.EnableEnvoyConfig)

	flags.String(option.IPMasqAgentConfigPath, "/etc/config/ip-masq-agent", "ip-masq-agent configuration file path")
	option.BindEnv(vp, option.IPMasqAgentConfigPath)

	flags.Bool(option.InstallIptRules, true, "Install base iptables rules for cilium to mainly interact with kube-proxy (and masquerading)")
	flags.MarkHidden(option.InstallIptRules)
	option.BindEnv(vp, option.InstallIptRules)

	flags.Int(option.MaxCtrlIntervalName, 0, "Maximum interval (in seconds) between controller runs. Zero is no limit.")
	flags.MarkHidden(option.MaxCtrlIntervalName)
	option.BindEnv(vp, option.MaxCtrlIntervalName)

	flags.String(option.MonitorAggregationName, "None",
		"Level of monitor aggregation for traces from the datapath")
	option.BindEnvWithLegacyEnvFallback(vp, option.MonitorAggregationName, "CILIUM_MONITOR_AGGREGATION_LEVEL")

	flags.Int(option.MTUName, 0, "Overwrite auto-detected MTU of underlying network")
	option.BindEnv(vp, option.MTUName)

	flags.Int(option.RouteMetric, 0, "Overwrite the metric used by cilium when adding routes to its 'cilium_host' device")
	option.BindEnv(vp, option.RouteMetric)

	flags.String(option.IPv6NodeAddr, "auto", "IPv6 address of node")
	option.BindEnv(vp, option.IPv6NodeAddr)

	flags.String(option.IPv4NodeAddr, "auto", "IPv4 address of node")
	option.BindEnv(vp, option.IPv4NodeAddr)

	flags.Bool(option.Restore, true, "Restores state, if possible, from previous daemon")
	option.BindEnv(vp, option.Restore)

	flags.String(option.SocketPath, defaults.SockPath, "Sets daemon's socket path to listen for connections")
	option.BindEnv(vp, option.SocketPath)

	flags.String(option.StateDir, defaults.RuntimePath, "Directory path to store runtime state")
	option.BindEnv(vp, option.StateDir)

	flags.Bool(option.ExternalEnvoyProxy, false, "whether the Envoy is deployed externally in form of a DaemonSet or not")
	option.BindEnv(vp, option.ExternalEnvoyProxy)

	flags.String(option.RoutingMode, defaults.RoutingMode, fmt.Sprintf("Routing mode (%q or %q)", option.RoutingModeNative, option.RoutingModeTunnel))
	option.BindEnv(vp, option.RoutingMode)

	flags.String(option.ServiceNoBackendResponse, defaults.ServiceNoBackendResponse, "Response to traffic for a service without backends")
	option.BindEnv(vp, option.ServiceNoBackendResponse)

	flags.Int(option.TracePayloadlen, 128, "Length of payload to capture when tracing")
	option.BindEnv(vp, option.TracePayloadlen)

	flags.Bool(option.Version, false, "Print version information")
	option.BindEnv(vp, option.Version)

	flags.Bool(option.EnableXDPPrefilter, false, "Enable XDP prefiltering")
	option.BindEnv(vp, option.EnableXDPPrefilter)

	flags.Bool(option.EnableTCX, true, "Attach endpoint programs using tcx if supported by the kernel")
	option.BindEnv(vp, option.EnableTCX)

	flags.Bool(option.PreAllocateMapsName, defaults.PreAllocateMaps, "Enable BPF map pre-allocation")
	option.BindEnv(vp, option.PreAllocateMapsName)

	flags.Int(option.AuthMapEntriesName, option.AuthMapEntriesDefault, "Maximum number of entries in auth map")
	option.BindEnv(vp, option.AuthMapEntriesName)

	flags.Int(option.CTMapEntriesGlobalTCPName, option.CTMapEntriesGlobalTCPDefault, "Maximum number of entries in TCP CT table")
	option.BindEnvWithLegacyEnvFallback(vp, option.CTMapEntriesGlobalTCPName, "CILIUM_GLOBAL_CT_MAX_TCP")

	flags.Int(option.CTMapEntriesGlobalAnyName, option.CTMapEntriesGlobalAnyDefault, "Maximum number of entries in non-TCP CT table")
	option.BindEnvWithLegacyEnvFallback(vp, option.CTMapEntriesGlobalAnyName, "CILIUM_GLOBAL_CT_MAX_ANY")

	flags.Duration(option.CTMapEntriesTimeoutTCPName, 8000*time.Second, "Timeout for established entries in TCP CT table")
	option.BindEnv(vp, option.CTMapEntriesTimeoutTCPName)

	flags.Duration(option.CTMapEntriesTimeoutAnyName, 60*time.Second, "Timeout for entries in non-TCP CT table")
	option.BindEnv(vp, option.CTMapEntriesTimeoutAnyName)

	flags.Duration(option.CTMapEntriesTimeoutSVCTCPName, 8000*time.Second, "Timeout for established service entries in TCP CT table")
	option.BindEnv(vp, option.CTMapEntriesTimeoutSVCTCPName)

	flags.Duration(option.CTMapEntriesTimeoutSVCTCPGraceName, 60*time.Second, "Timeout for graceful shutdown of service entries in TCP CT table")
	option.BindEnv(vp, option.CTMapEntriesTimeoutSVCTCPGraceName)

	flags.Duration(option.CTMapEntriesTimeoutSVCAnyName, 60*time.Second, "Timeout for service entries in non-TCP CT table")
	option.BindEnv(vp, option.CTMapEntriesTimeoutSVCAnyName)

	flags.Duration(option.CTMapEntriesTimeoutSYNName, 60*time.Second, "Establishment timeout for entries in TCP CT table")
	option.BindEnv(vp, option.CTMapEntriesTimeoutSYNName)

	flags.Duration(option.CTMapEntriesTimeoutFINName, 10*time.Second, "Teardown timeout for entries in TCP CT table")
	option.BindEnv(vp, option.CTMapEntriesTimeoutFINName)

	flags.Duration(option.MonitorAggregationInterval, 5*time.Second, "Monitor report interval when monitor aggregation is enabled")
	option.BindEnv(vp, option.MonitorAggregationInterval)

	flags.StringSlice(option.MonitorAggregationFlags, option.MonitorAggregationFlagsDefault, "TCP flags that trigger monitor reports when monitor aggregation is enabled")
	option.BindEnv(vp, option.MonitorAggregationFlags)

	flags.Int(option.NATMapEntriesGlobalName, option.NATMapEntriesGlobalDefault, "Maximum number of entries for the global BPF NAT table")
	option.BindEnv(vp, option.NATMapEntriesGlobalName)

	flags.Int(option.NeighMapEntriesGlobalName, option.NATMapEntriesGlobalDefault, "Maximum number of entries for the global BPF neighbor table")
	option.BindEnv(vp, option.NeighMapEntriesGlobalName)

	flags.Int(option.PolicyMapEntriesName, policymap.MaxEntries, "Maximum number of entries in endpoint policy map (per endpoint)")
	option.BindEnv(vp, option.PolicyMapEntriesName)

	flags.Duration(option.PolicyMapFullReconciliationIntervalName, 15*time.Minute, "Interval for full reconciliation of endpoint policy map")
	option.BindEnv(vp, option.PolicyMapFullReconciliationIntervalName)
	flags.MarkHidden(option.PolicyMapFullReconciliationIntervalName)

	flags.Int(option.SockRevNatEntriesName, option.SockRevNATMapEntriesDefault, "Maximum number of entries for the SockRevNAT BPF map")
	option.BindEnv(vp, option.SockRevNatEntriesName)

	flags.Float64(option.MapEntriesGlobalDynamicSizeRatioName, 0.0025, "Ratio (0.0-1.0] of total system memory to use for dynamic sizing of CT, NAT and policy BPF maps")
	option.BindEnv(vp, option.MapEntriesGlobalDynamicSizeRatioName)

	flags.String(option.CMDRef, "", "Path to cmdref output directory")
	flags.MarkHidden(option.CMDRef)
	option.BindEnv(vp, option.CMDRef)

	flags.Int(option.ToFQDNsMinTTL, defaults.ToFQDNsMinTTL, "The minimum time, in seconds, to use DNS data for toFQDNs policies")
	option.BindEnv(vp, option.ToFQDNsMinTTL)

	flags.Int(option.ToFQDNsProxyPort, 0, "Global port on which the in-agent DNS proxy should listen. Default 0 is a OS-assigned port.")
	option.BindEnv(vp, option.ToFQDNsProxyPort)

	flags.String(option.FQDNRejectResponseCode, option.FQDNProxyDenyWithRefused, fmt.Sprintf("DNS response code for rejecting DNS requests, available options are '%v'", option.FQDNRejectOptions))
	option.BindEnv(vp, option.FQDNRejectResponseCode)

	flags.Int(option.ToFQDNsMaxIPsPerHost, defaults.ToFQDNsMaxIPsPerHost, "Maximum number of IPs to maintain per FQDN name for each endpoint")
	option.BindEnv(vp, option.ToFQDNsMaxIPsPerHost)

	flags.Int(option.DNSMaxIPsPerRestoredRule, defaults.DNSMaxIPsPerRestoredRule, "Maximum number of IPs to maintain for each restored DNS rule")
	option.BindEnv(vp, option.DNSMaxIPsPerRestoredRule)

	flags.Bool(option.DNSPolicyUnloadOnShutdown, false, "Unload DNS policy rules on graceful shutdown")
	option.BindEnv(vp, option.DNSPolicyUnloadOnShutdown)

	flags.Int(option.ToFQDNsMaxDeferredConnectionDeletes, defaults.ToFQDNsMaxDeferredConnectionDeletes, "Maximum number of IPs to retain for expired DNS lookups with still-active connections")
	option.BindEnv(vp, option.ToFQDNsMaxDeferredConnectionDeletes)

	flags.Duration(option.ToFQDNsIdleConnectionGracePeriod, defaults.ToFQDNsIdleConnectionGracePeriod, "Time during which idle but previously active connections with expired DNS lookups are still considered alive (default 0s)")
	option.BindEnv(vp, option.ToFQDNsIdleConnectionGracePeriod)

	flags.Duration(option.FQDNProxyResponseMaxDelay, defaults.FQDNProxyResponseMaxDelay, "The maximum time the DNS proxy holds an allowed DNS response before sending it along. Responses are sent as soon as the datapath is updated with the new IP information.")
	option.BindEnv(vp, option.FQDNProxyResponseMaxDelay)

	flags.Int(option.FQDNRegexCompileLRUSize, defaults.FQDNRegexCompileLRUSize, "Size of the FQDN regex compilation LRU. Useful for heavy but repeated DNS L7 rules with MatchName or MatchPattern")
	flags.MarkHidden(option.FQDNRegexCompileLRUSize)
	option.BindEnv(vp, option.FQDNRegexCompileLRUSize)

	flags.String(option.ToFQDNsPreCache, defaults.ToFQDNsPreCache, "DNS cache data at this path is preloaded on agent startup")
	option.BindEnv(vp, option.ToFQDNsPreCache)

	flags.Bool(option.ToFQDNsEnableDNSCompression, defaults.ToFQDNsEnableDNSCompression, "Allow the DNS proxy to compress responses to endpoints that are larger than 512 Bytes or the EDNS0 option, if present")
	option.BindEnv(vp, option.ToFQDNsEnableDNSCompression)

	flags.Int(option.DNSProxyConcurrencyLimit, 0, "Limit concurrency of DNS message processing")
	option.BindEnv(vp, option.DNSProxyConcurrencyLimit)

	flags.Duration(option.DNSProxyConcurrencyProcessingGracePeriod, 0, "Grace time to wait when DNS proxy concurrent limit has been reached during DNS message processing")
	option.BindEnv(vp, option.DNSProxyConcurrencyProcessingGracePeriod)

	flags.Int(option.DNSProxyLockCount, defaults.DNSProxyLockCount, "Array size containing mutexes which protect against parallel handling of DNS response names. Preferably use prime numbers")
	flags.MarkHidden(option.DNSProxyLockCount)
	option.BindEnv(vp, option.DNSProxyLockCount)

	flags.Duration(option.DNSProxyLockTimeout, defaults.DNSProxyLockTimeout, fmt.Sprintf("Timeout when acquiring the locks controlled by --%s", option.DNSProxyLockCount))
	flags.MarkHidden(option.DNSProxyLockTimeout)
	option.BindEnv(vp, option.DNSProxyLockTimeout)

	flags.Int(option.DNSProxySocketLingerTimeout, defaults.DNSProxySocketLingerTimeout, "Timeout (in seconds) when closing the connection between the DNS proxy and the upstream server. "+
		"If set to 0, the connection is closed immediately (with TCP RST). If set to -1, the connection is closed asynchronously in the background")
	option.BindEnv(vp, option.DNSProxySocketLingerTimeout)

	flags.Bool(option.DNSProxyEnableTransparentMode, defaults.DNSProxyEnableTransparentMode, "Enable DNS proxy transparent mode")
	option.BindEnv(vp, option.DNSProxyEnableTransparentMode)

	flags.Bool(option.DNSProxyInsecureSkipTransparentModeCheck, false, "Allows DNS proxy transparent mode to be disabled even if encryption is enabled. Enabling this flag and disabling DNS proxy transparent mode will cause proxied DNS traffic to leave the node unencrypted.")
	flags.MarkHidden(option.DNSProxyInsecureSkipTransparentModeCheck)
	option.BindEnv(vp, option.DNSProxyInsecureSkipTransparentModeCheck)

	flags.Int(option.PolicyQueueSize, defaults.PolicyQueueSize, "Size of queues for policy-related events")
	option.BindEnv(vp, option.PolicyQueueSize)

	flags.Int(option.EndpointQueueSize, defaults.EndpointQueueSize, "Size of EventQueue per-endpoint")
	option.BindEnv(vp, option.EndpointQueueSize)

	flags.Duration(option.PolicyTriggerInterval, defaults.PolicyTriggerInterval, "Time between triggers of policy updates (regenerations for all endpoints)")
	flags.MarkHidden(option.PolicyTriggerInterval)
	option.BindEnv(vp, option.PolicyTriggerInterval)

	flags.Bool(option.PolicyAuditModeArg, false, "Enable policy audit (non-drop) mode")
	option.BindEnv(vp, option.PolicyAuditModeArg)

	flags.Bool(option.PolicyAccountingArg, true, "Enable policy accounting")
	option.BindEnv(vp, option.PolicyAccountingArg)

	flags.Bool(option.EnableHubble, false, "Enable hubble server")
	option.BindEnv(vp, option.EnableHubble)

	flags.String(option.HubbleSocketPath, defaults.HubbleSockPath, "Set hubble's socket path to listen for connections")
	option.BindEnv(vp, option.HubbleSocketPath)

	flags.String(option.HubbleListenAddress, "", `An additional address for Hubble server to listen to, e.g. ":4244"`)
	option.BindEnv(vp, option.HubbleListenAddress)

	flags.Bool(option.HubblePreferIpv6, false, "Prefer IPv6 addresses for announcing nodes when both address types are available.")
	option.BindEnv(vp, option.HubblePreferIpv6)

	flags.Bool(option.HubbleTLSDisabled, false, "Allow Hubble server to run on the given listen address without TLS.")
	option.BindEnv(vp, option.HubbleTLSDisabled)

	flags.String(option.HubbleTLSCertFile, "", "Path to the public key file for the Hubble server. The file must contain PEM encoded data.")
	option.BindEnv(vp, option.HubbleTLSCertFile)

	flags.String(option.HubbleTLSKeyFile, "", "Path to the private key file for the Hubble server. The file must contain PEM encoded data.")
	option.BindEnv(vp, option.HubbleTLSKeyFile)

	flags.StringSlice(option.HubbleTLSClientCAFiles, []string{}, "Paths to one or more public key files of client CA certificates to use for TLS with mutual authentication (mTLS). The files must contain PEM encoded data. When provided, this option effectively enables mTLS.")
	option.BindEnv(vp, option.HubbleTLSClientCAFiles)

	flags.Int(option.HubbleEventBufferCapacity, observeroption.Default.MaxFlows.AsInt(), "Capacity of Hubble events buffer. The provided value must be one less than an integer power of two and no larger than 65535 (ie: 1, 3, ..., 2047, 4095, ..., 65535)")
	option.BindEnv(vp, option.HubbleEventBufferCapacity)

	flags.Int(option.HubbleEventQueueSize, 0, "Buffer size of the channel to receive monitor events.")
	option.BindEnv(vp, option.HubbleEventQueueSize)

	flags.String(option.HubbleMetricsServer, "", "Address to serve Hubble metrics on.")
	option.BindEnv(vp, option.HubbleMetricsServer)

	flags.StringSlice(option.HubbleMetrics, []string{}, "List of Hubble metrics to enable.")
	option.BindEnv(vp, option.HubbleMetrics)

	flags.String(option.HubbleFlowlogsConfigFilePath, "", "Filepath with configuration of hubble flowlogs")
	option.BindEnv(vp, option.HubbleFlowlogsConfigFilePath)

	flags.String(option.HubbleExportFilePath, exporteroption.Default.Path, "Filepath to write Hubble events to. By specifying `stdout` the flows are logged instead of written to a rotated file.")
	option.BindEnv(vp, option.HubbleExportFilePath)

	flags.Int(option.HubbleExportFileMaxSizeMB, exporteroption.Default.MaxSizeMB, "Size in MB at which to rotate Hubble export file.")
	option.BindEnv(vp, option.HubbleExportFileMaxSizeMB)

	flags.Int(option.HubbleExportFileMaxBackups, exporteroption.Default.MaxBackups, "Number of rotated Hubble export files to keep.")
	option.BindEnv(vp, option.HubbleExportFileMaxBackups)

	flags.Bool(option.HubbleExportFileCompress, exporteroption.Default.Compress, "Compress rotated Hubble export files.")
	option.BindEnv(vp, option.HubbleExportFileCompress)

	flags.StringSlice(option.HubbleExportAllowlist, []string{}, "Specify allowlist as JSON encoded FlowFilters to Hubble exporter.")
	option.BindEnv(vp, option.HubbleExportAllowlist)

	flags.StringSlice(option.HubbleExportDenylist, []string{}, "Specify denylist as JSON encoded FlowFilters to Hubble exporter.")
	option.BindEnv(vp, option.HubbleExportDenylist)

	flags.StringSlice(option.HubbleExportFieldmask, []string{}, "Specify list of fields to use for field mask in Hubble exporter.")
	option.BindEnv(vp, option.HubbleExportFieldmask)

	flags.Bool(option.EnableHubbleRecorderAPI, true, "Enable the Hubble recorder API")
	option.BindEnv(vp, option.EnableHubbleRecorderAPI)

	flags.String(option.HubbleRecorderStoragePath, defaults.HubbleRecorderStoragePath, "Directory in which pcap files created via the Hubble Recorder API are stored")
	option.BindEnv(vp, option.HubbleRecorderStoragePath)

	flags.Int(option.HubbleRecorderSinkQueueSize, defaults.HubbleRecorderSinkQueueSize, "Queue size of each Hubble recorder sink")
	option.BindEnv(vp, option.HubbleRecorderSinkQueueSize)

	flags.Bool(option.HubbleSkipUnknownCGroupIDs, true, "Skip Hubble events with unknown cgroup ids")
	option.BindEnv(vp, option.HubbleSkipUnknownCGroupIDs)

	flags.StringSlice(option.HubbleMonitorEvents, []string{},
		fmt.Sprintf(
			"Cilium monitor events for Hubble to observe: [%s]. By default, Hubble observes all monitor events.",
			strings.Join(monitorAPI.AllMessageTypeNames(), " "),
		),
	)
	option.BindEnv(vp, option.HubbleMonitorEvents)

	flags.Bool(option.HubbleRedactEnabled, defaults.HubbleRedactEnabled, "Hubble redact sensitive information from flows")
	option.BindEnv(vp, option.HubbleRedactEnabled)

	flags.Bool(option.HubbleRedactHttpURLQuery, defaults.HubbleRedactHttpURLQuery, "Hubble redact http URL query from flows")
	option.BindEnv(vp, option.HubbleRedactHttpURLQuery)

	flags.Bool(option.HubbleRedactHttpUserInfo, defaults.HubbleRedactHttpUserInfo, "Hubble redact http user info from flows")
	option.BindEnv(vp, option.HubbleRedactHttpUserInfo)

	flags.Bool(option.HubbleRedactKafkaApiKey, defaults.HubbleRedactKafkaApiKey, "Hubble redact Kafka API key from flows")
	option.BindEnv(vp, option.HubbleRedactKafkaApiKey)

	flags.StringSlice(option.HubbleRedactHttpHeadersAllow, []string{}, "HTTP headers to keep visible in flows")
	option.BindEnv(vp, option.HubbleRedactHttpHeadersAllow)

	flags.StringSlice(option.HubbleRedactHttpHeadersDeny, []string{}, "HTTP headers to redact from flows")
	option.BindEnv(vp, option.HubbleRedactHttpHeadersDeny)

	flags.Bool(option.HubbleDropEvents, defaults.HubbleDropEventsEnabled, "Emit packet drop Events related to pods (alpha)")
	option.BindEnv(vp, option.HubbleDropEvents)

	flags.Duration(option.HubbleDropEventsInterval, defaults.HubbleDropEventsInterval, "Minimum time between emitting same events")
	option.BindEnv(vp, option.HubbleDropEventsInterval)

	flags.String(option.HubbleDropEventsReasons, defaults.HubbleDropEventsReasons, "Drop reasons to emit events for")
	option.BindEnv(vp, option.HubbleDropEventsReasons)

	flags.Bool(option.EnableIPv4FragmentsTrackingName, defaults.EnableIPv4FragmentsTracking, "Enable IPv4 fragments tracking for L4-based lookups")
	option.BindEnv(vp, option.EnableIPv4FragmentsTrackingName)

	flags.Int(option.FragmentsMapEntriesName, defaults.FragmentsMapEntries, "Maximum number of entries in fragments tracking map")
	option.BindEnv(vp, option.FragmentsMapEntriesName)

	flags.Int(option.LBMapEntriesName, lbmap.DefaultMaxEntries, "Maximum number of entries in Cilium BPF lbmap")
	option.BindEnv(vp, option.LBMapEntriesName)

	flags.Int(option.BPFEventsDefaultRateLimit, 0, fmt.Sprintf("Limit of average number of messages per second that can be written to BPF events map (if set, --%s value must also be specified). If both --%s and --%s are 0 or not specified, no limit is imposed.", option.BPFEventsDefaultBurstLimit, option.BPFEventsDefaultRateLimit, option.BPFEventsDefaultBurstLimit))
	flags.MarkHidden(option.BPFEventsDefaultRateLimit)
	option.BindEnv(vp, option.BPFEventsDefaultRateLimit)

	flags.Int(option.BPFEventsDefaultBurstLimit, 0, fmt.Sprintf("Maximum number of messages that can be written to BPF events map in 1 second (if set, --%s value must also be specified). If both --%s and --%s are 0 or not specified, no limit is imposed.", option.BPFEventsDefaultRateLimit, option.BPFEventsDefaultBurstLimit, option.BPFEventsDefaultRateLimit))
	flags.MarkHidden(option.BPFEventsDefaultBurstLimit)
	option.BindEnv(vp, option.BPFEventsDefaultBurstLimit)

	flags.Int(option.LBServiceMapMaxEntries, 0, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for services (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBServiceMapMaxEntries)
	option.BindEnv(vp, option.LBServiceMapMaxEntries)

	flags.Int(option.LBBackendMapMaxEntries, 0, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for service backends (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBBackendMapMaxEntries)
	option.BindEnv(vp, option.LBBackendMapMaxEntries)

	flags.Int(option.LBRevNatMapMaxEntries, 0, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for reverse NAT (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBRevNatMapMaxEntries)
	option.BindEnv(vp, option.LBRevNatMapMaxEntries)

	flags.Int(option.LBAffinityMapMaxEntries, 0, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for session affinities (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBAffinityMapMaxEntries)
	option.BindEnv(vp, option.LBAffinityMapMaxEntries)

	flags.Int(option.LBSourceRangeMapMaxEntries, 0, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for source ranges (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBSourceRangeMapMaxEntries)
	option.BindEnv(vp, option.LBSourceRangeMapMaxEntries)

	flags.Int(option.LBMaglevMapMaxEntries, 0, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for maglev (if this isn't set, the value of --%s will be used.)", option.LBMapEntriesName))
	flags.MarkHidden(option.LBMaglevMapMaxEntries)
	option.BindEnv(vp, option.LBMaglevMapMaxEntries)

	flags.String(option.LocalRouterIPv4, "", "Link-local IPv4 used for Cilium's router devices")
	option.BindEnv(vp, option.LocalRouterIPv4)

	flags.String(option.LocalRouterIPv6, "", "Link-local IPv6 used for Cilium's router devices")
	option.BindEnv(vp, option.LocalRouterIPv6)

	flags.Var(option.NewNamedMapOptions(option.BPFMapEventBuffers, &option.Config.BPFMapEventBuffers, option.Config.BPFMapEventBuffersValidator), option.BPFMapEventBuffers, "Configuration for BPF map event buffers: (example: --bpf-map-event-buffers cilium_ipcache=true,1024,1h)")
	flags.MarkHidden(option.BPFMapEventBuffers)

	flags.Duration(option.CRDWaitTimeout, 5*time.Minute, "Cilium will exit if CRDs are not available within this duration upon startup")
	option.BindEnv(vp, option.CRDWaitTimeout)

	flags.Bool(option.EgressMultiHomeIPRuleCompat, false,
		"Offset routing table IDs under ENI IPAM mode to avoid collisions with reserved table IDs. If false, the offset is performed (new scheme), otherwise, the old scheme stays in-place.")
	option.BindEnv(vp, option.EgressMultiHomeIPRuleCompat)

	flags.Bool(option.InstallNoConntrackIptRules, defaults.InstallNoConntrackIptRules, "Install Iptables rules to skip netfilter connection tracking on all pod traffic. This option is only effective when Cilium is running in direct routing and full KPR mode. Moreover, this option cannot be enabled when Cilium is running in a managed Kubernetes environment or in a chained CNI setup.")
	option.BindEnv(vp, option.InstallNoConntrackIptRules)

	flags.String(option.ContainerIPLocalReservedPorts, defaults.ContainerIPLocalReservedPortsAuto, "Instructs the Cilium CNI plugin to reserve the provided comma-separated list of ports in the container network namespace. "+
		"Prevents the container from using these ports as ephemeral source ports (see Linux ip_local_reserved_ports). Use this flag if you observe port conflicts between transparent DNS proxy requests and host network namespace services. "+
		"Value \"auto\" reserves the WireGuard and VXLAN ports used by Cilium")
	option.BindEnv(vp, option.ContainerIPLocalReservedPorts)

	flags.Bool(option.EnableCustomCallsName, false, "Enable tail call hooks for custom eBPF programs")
	option.BindEnv(vp, option.EnableCustomCallsName)

	flags.Bool(option.BGPAnnounceLBIP, false, "Announces service IPs of type LoadBalancer via BGP")
	option.BindEnv(vp, option.BGPAnnounceLBIP)

	flags.Bool(option.BGPAnnouncePodCIDR, false, "Announces the node's pod CIDR via BGP")
	option.BindEnv(vp, option.BGPAnnouncePodCIDR)

	flags.String(option.BGPConfigPath, "/var/lib/cilium/bgp/config.yaml", "Path to file containing the BGP configuration")
	option.BindEnv(vp, option.BGPConfigPath)

	flags.Bool(option.ExternalClusterIPName, false, "Enable external access to ClusterIP services (default false)")
	option.BindEnv(vp, option.ExternalClusterIPName)

	// flags.IntSlice cannot be used due to missing support for appropriate conversion in Viper.
	// See https://github.com/cilium/cilium/pull/20282 for more information.
	flags.StringSlice(option.VLANBPFBypass, []string{}, "List of explicitly allowed VLAN IDs, '0' id will allow all VLAN IDs")
	option.BindEnv(vp, option.VLANBPFBypass)

	flags.Bool(option.DisableExternalIPMitigation, false, "Disable ExternalIP mitigation (CVE-2020-8554, default false)")
	option.BindEnv(vp, option.DisableExternalIPMitigation)

	flags.Bool(option.EnableICMPRules, true, "Enable ICMP-based rule support for Cilium Network Policies")
	flags.MarkHidden(option.EnableICMPRules)
	option.BindEnv(vp, option.EnableICMPRules)

	flags.Bool(option.UseCiliumInternalIPForIPsec, defaults.UseCiliumInternalIPForIPsec, "Use the CiliumInternalIPs (vs. NodeInternalIPs) for IPsec encapsulation")
	flags.MarkHidden(option.UseCiliumInternalIPForIPsec)
	option.BindEnv(vp, option.UseCiliumInternalIPForIPsec)

	flags.Bool(option.BypassIPAvailabilityUponRestore, false, "Bypasses the IP availability error within IPAM upon endpoint restore")
	flags.MarkHidden(option.BypassIPAvailabilityUponRestore)
	option.BindEnv(vp, option.BypassIPAvailabilityUponRestore)

	flags.Bool(option.EnableCiliumEndpointSlice, false, "Enable the CiliumEndpointSlice watcher in place of the CiliumEndpoint watcher (beta)")
	option.BindEnv(vp, option.EnableCiliumEndpointSlice)

	flags.Bool(option.EnableK8sTerminatingEndpoint, true, "Enable auto-detect of terminating endpoint condition")
	option.BindEnv(vp, option.EnableK8sTerminatingEndpoint)

	flags.Bool(option.EnableVTEP, defaults.EnableVTEP, "Enable  VXLAN Tunnel Endpoint (VTEP) Integration (beta)")
	option.BindEnv(vp, option.EnableVTEP)

	flags.StringSlice(option.VtepEndpoint, []string{}, "List of VTEP IP addresses")
	option.BindEnv(vp, option.VtepEndpoint)

	flags.StringSlice(option.VtepCIDR, []string{}, "List of VTEP CIDRs that will be routed towards VTEPs for traffic cluster egress")
	option.BindEnv(vp, option.VtepCIDR)

	flags.String(option.VtepMask, "255.255.255.0", "VTEP CIDR Mask for all VTEP CIDRs")
	option.BindEnv(vp, option.VtepMask)

	flags.StringSlice(option.VtepMAC, []string{}, "List of VTEP MAC addresses for forwarding traffic outside the cluster")
	option.BindEnv(vp, option.VtepMAC)

	flags.Int(option.TCFilterPriority, 1, "Priority of TC BPF filter")
	flags.MarkHidden(option.TCFilterPriority)
	option.BindEnv(vp, option.TCFilterPriority)

	flags.Bool(option.EnableBGPControlPlane, false, "Enable the BGP control plane.")
	option.BindEnv(vp, option.EnableBGPControlPlane)

	flags.Bool(option.EnablePMTUDiscovery, false, "Enable path MTU discovery to send ICMP fragmentation-needed replies to the client")
	option.BindEnv(vp, option.EnablePMTUDiscovery)

	flags.Duration(option.IPAMCiliumNodeUpdateRate, 15*time.Second, "Maximum rate at which the CiliumNode custom resource is updated")
	option.BindEnv(vp, option.IPAMCiliumNodeUpdateRate)

	flags.Bool(option.EnableK8sNetworkPolicy, defaults.EnableK8sNetworkPolicy, "Enable support for K8s NetworkPolicy")
	flags.MarkHidden(option.EnableK8sNetworkPolicy)
	option.BindEnv(vp, option.EnableK8sNetworkPolicy)

	flags.StringSlice(option.PolicyCIDRMatchMode, defaults.PolicyCIDRMatchMode, "The entities that can be selected by CIDR policy. Supported values: 'nodes'")
	option.BindEnv(vp, option.PolicyCIDRMatchMode)

	flags.Duration(option.MaxInternalTimerDelay, defaults.MaxInternalTimerDelay, "Maximum internal timer value across the entire agent. Use in test environments to detect race conditions in agent logic.")
	flags.MarkHidden(option.MaxInternalTimerDelay)
	option.BindEnv(vp, option.MaxInternalTimerDelay)

	flags.Bool(option.EnableNodeSelectorLabels, defaults.EnableNodeSelectorLabels, "Enable use of node label based identity")
	option.BindEnv(vp, option.EnableNodeSelectorLabels)

	flags.StringSlice(option.NodeLabels, []string{}, "List of label prefixes used to determine identity of a node (used only when enable-node-selector-labels is enabled)")
	option.BindEnv(vp, option.NodeLabels)

	if err := vp.BindPFlags(flags); err != nil {
		log.Fatalf("BindPFlags failed: %s", err)
	}
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

func initLogging() {
	// add hooks after setting up metrics in the option.Config
	logging.DefaultLogger.Hooks.Add(metrics.NewLoggingHook())

	// Logging should always be bootstrapped first. Do not add any code above this!
	if err := logging.SetupLogging(option.Config.LogDriver, logging.LogOptions(option.Config.LogOpt), "cilium-agent", option.Config.Debug); err != nil {
		log.Fatal(err)
	}
}

func initDaemonConfig(vp *viper.Viper) {
	option.Config.SetMapElementSizes(
		// for the conntrack and NAT element size we assume the largest possible
		// key size, i.e. IPv6 keys
		ctmap.SizeofCtKey6Global+ctmap.SizeofCtEntry,
		nat.SizeofNatKey6+nat.SizeofNatEntry6,
		neighborsmap.SizeofNeighKey6+neighborsmap.SizeOfNeighValue,
		lbmap.SizeofSockRevNat6Key+lbmap.SizeofSockRevNat6Value)

	option.Config.Populate(vp)

	time.MaxInternalTimerDelay = vp.GetDuration(option.MaxInternalTimerDelay)
}

func initEnv(vp *viper.Viper) {
	bootstrapStats.earlyInit.Start()
	defer bootstrapStats.earlyInit.End(true)

	var debugDatapath bool

	option.LogRegisteredOptions(vp, log)

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

	// Creating Envoy sockets directory for cases which doesn't provide a volume mount
	// (e.g. embedded Envoy, external workload in ClusterMesh scenario)
	if err := os.MkdirAll(envoy.GetSocketDir(option.Config.RunDir), defaults.RuntimePathRights); err != nil {
		scopedLog.WithError(err).Fatal("Could not create envoy sockets directory")
	}

	if option.Config.MaxControllerInterval < 0 {
		scopedLog.Fatalf("Invalid %s value %d", option.MaxCtrlIntervalName, option.Config.MaxControllerInterval)
	}

	// set rlimit Memlock to INFINITY before creating any bpf resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.WithError(err).Fatal("unable to set memory resource limits")
	}

	globalsDir := option.Config.GetGlobalsDir()
	if err := os.MkdirAll(globalsDir, defaults.StateDirRights); err != nil {
		log.WithError(err).WithField(logfields.Path, globalsDir).Fatal("Could not create runtime directory")
	}
	if err := os.Chdir(option.Config.LibDir); err != nil {
		log.WithError(err).WithField(logfields.Path, option.Config.LibDir).Fatal("Could not change to runtime directory")
	}
	if _, err := os.Stat(option.Config.BpfDir); os.IsNotExist(err) {
		log.WithError(err).Fatalf("BPF template directory: NOT OK. Please run 'make install-bpf'")
	}

	if err := probes.CreateHeaderFiles(filepath.Join(option.Config.BpfDir, "include/bpf"), probes.ExecuteHeaderProbes()); err != nil {
		log.WithError(err).Fatal("failed to create header files with feature macros")
	}

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
	option.Config.Opts.SetBool(option.DropNotify, option.Config.BPFEventsDropEnabled)
	option.Config.Opts.SetBool(option.PolicyVerdictNotify, option.Config.BPFEventsPolicyVerdictEnabled)
	option.Config.Opts.SetBool(option.TraceNotify, option.Config.BPFEventsTraceEnabled)
	option.Config.Opts.SetBool(option.PolicyTracing, option.Config.EnableTracing)
	option.Config.Opts.SetBool(option.ConntrackAccounting, false)
	option.Config.Opts.SetBool(option.ConntrackLocal, false)
	option.Config.Opts.SetBool(option.PolicyAuditMode, option.Config.PolicyAuditMode)
	option.Config.Opts.SetBool(option.PolicyAccounting, option.Config.PolicyAccounting)
	option.Config.Opts.SetBool(option.SourceIPVerification, true)

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
	if err := labelsfilter.ParseLabelPrefixCfg(option.Config.Labels, option.Config.NodeLabels, option.Config.LabelPrefixFile); err != nil {
		log.WithError(err).Fatal("Unable to parse Label prefix configuration")
	}

	switch option.Config.DatapathMode {
	case datapathOption.DatapathModeVeth:
	case datapathOption.DatapathModeNetkit, datapathOption.DatapathModeNetkitL2:
		// For netkit we enable also tcx for all non-netkit devices.
		// The underlying kernel does support it given tcx got merged
		// before netkit and supporting legacy tc in this context does
		// not make any sense whatsoever.
		option.Config.EnableTCX = true
	case datapathOption.DatapathModeLBOnly:
		log.Info("Running in LB-only mode")
		if option.Config.NodePortAcceleration != option.NodePortAccelerationDisabled {
			option.Config.EnablePMTUDiscovery = true
		}
		option.Config.KubeProxyReplacement = option.KubeProxyReplacementFalse
		option.Config.EnableSocketLB = true
		option.Config.EnableSocketLBPodConnectionTermination = true
		option.Config.EnableHostPort = false
		option.Config.EnableNodePort = true
		option.Config.EnableExternalIPs = true
		option.Config.RoutingMode = option.RoutingModeNative
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

	if !option.Config.DNSProxyInsecureSkipTransparentModeCheck {
		if option.Config.EnableIPSec && option.Config.EnableL7Proxy && !option.Config.DNSProxyEnableTransparentMode {
			log.Fatal("IPSec requires DNS proxy transparent mode to be enabled (--dnsproxy-enable-transparent-mode=\"true\")")
		}
	}

	if option.Config.EnableIPSec && !option.Config.EnableIPv4 {
		log.Fatal("IPSec requires IPv4 addressing to be enabled (--enable-ipv4=\"true\")")
	}

	if option.Config.EnableIPSec && option.Config.TunnelingEnabled() {
		if err := ipsec.ProbeXfrmStateOutputMask(); err != nil {
			log.WithError(err).Fatal("IPSec with tunneling requires support for xfrm state output masks (Linux 4.19 or later).")
		}
	}

	if option.Config.EnableIPSecEncryptedOverlay && !option.Config.EnableIPSec {
		log.Warn("IPSec encrypted overlay is enabled but IPSec is not. Ignoring option.")
	}

	// IPAMENI IPSec is configured from Reinitialize() to pull in devices
	// that may be added or removed at runtime.
	if option.Config.EnableIPSec &&
		!option.Config.TunnelingEnabled() &&
		len(option.Config.EncryptInterface) == 0 &&
		// If devices are required, we don't look at the EncryptInterface, as we
		// don't load bpf_network in loader.reinitializeIPSec. Instead, we load
		// bpf_host onto physical devices as chosen by configuration.
		!option.Config.AreDevicesRequired() &&
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

	if option.Config.EnableSRv6 {
		if !option.Config.EnableIPv6 {
			log.Fatalf("SRv6 requires IPv6.")
		}
	}

	if option.Config.EnableHostFirewall {
		if option.Config.EnableIPSec {
			log.Fatal("IPSec cannot be used with the host firewall.")
		}
	}

	if option.Config.EnableHighScaleIPcache {
		if option.Config.TunnelingEnabled() {
			log.Fatal("The high-scale IPcache mode requires native routing.")
		}
		if option.Config.EnableIPSec {
			log.Fatal("IPsec is not supported in high scale IPcache mode.")
		}
		if option.Config.EnableIPv6 {
			log.Fatal("The high-scale IPcache mode is not supported with IPv6.")
		}
		if !option.Config.EnableWellKnownIdentities {
			log.Fatal("The high-scale IPcache mode requires well-known identities to be enabled.")
		}
		if err := probes.HaveOuterSourceIPSupport(); err != nil {
			log.WithError(err).Fatal("The high scale IPcache mode needs support in the kernel to set the outer source IP address.")
		}
	}

	if err := probes.HaveSKBAdjustRoomL2RoomMACSupport(); err != nil {
		if option.Config.ServiceNoBackendResponse != option.ServiceNoBackendResponseDrop {
			log.Warn("The kernel does not support --service-no-backend-response=reject, falling back to --service-no-backend-response=drop")
			option.Config.ServiceNoBackendResponse = option.ServiceNoBackendResponseDrop
		}
	}

	if option.Config.EnableIPv4FragmentsTracking {
		if !option.Config.EnableIPv4 {
			option.Config.EnableIPv4FragmentsTracking = false
		}
	}

	if option.Config.EnableBPFTProxy {
		if probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnSkAssign) != nil {
			option.Config.EnableBPFTProxy = false
			log.Info("Disabled support for BPF TProxy due to missing kernel support for socket assign (Linux 5.7 or later)")
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

	if option.Config.EnableEndpointRoutes && option.Config.EnableLocalNodeRoute {
		option.Config.EnableLocalNodeRoute = false
		log.Debugf(
			"Auto-set %q to `false` because it is redundant to per-endpoint routes (%s=true)",
			option.EnableLocalNodeRoute, option.EnableEndpointRoutes,
		)
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

	if option.Config.IPAM == ipamOption.IPAMMultiPool {
		if option.Config.TunnelingEnabled() {
			log.Fatalf("Cannot specify IPAM mode %s in tunnel mode.", option.Config.IPAM)
		}
		if option.Config.EnableIPSec {
			log.Fatalf("Cannot specify IPAM mode %s with %s.", option.Config.IPAM, option.EnableIPSecName)
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

func (d *Daemon) initKVStore(resolver *dial.ServiceResolver) {
	goopts := &kvstore.ExtraOptions{
		ClusterSizeDependantInterval: d.nodeDiscovery.Manager.ClusterSizeDependantInterval,
	}

	cg := controller.NewGroup("kvstore-locks-gc")
	controller.NewManager().UpdateController("kvstore-locks-gc",
		controller.ControllerParams{
			Group: cg,
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
	if d.clientset.IsEnabled() {
		log := log.WithField(logfields.LogSubsys, "etcd")
		goopts.DialOption = []grpc.DialOption{
			grpc.WithContextDialer(dial.NewContextDialer(log, resolver)),
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

// daemonCell wraps the existing implementation of the cilium-agent that has
// not yet been converted into a cell. Provides *Daemon as a Promise that is
// resolved once daemon has been started to facilitate conversion into modules.
var daemonCell = cell.Module(
	"daemon",
	"Legacy Daemon",

	cell.Provide(
		newDaemonPromise,
		promise.New[endpointstate.Restorer],
		newSyncHostIPs,
	),
	// Provide a read-only copy of the current daemon settings to be consumed
	// by the debuginfo API
	cell.ProvidePrivate(daemonSettings),
	cell.Invoke(registerEndpointStateResolver),
	cell.Invoke(func(promise.Promise[*Daemon]) {}), // Force instantiation.
	endpointBPFrogWatchdogCell,
)

type daemonParams struct {
	cell.In

	Lifecycle              cell.Lifecycle
	Health                 cell.Health
	Clientset              k8sClient.Clientset
	Datapath               datapath.Datapath
	WGAgent                *wireguard.Agent
	LocalNodeStore         *node.LocalNodeStore
	Shutdowner             hive.Shutdowner
	Resources              agentK8s.Resources
	K8sWatcher             *watchers.K8sWatcher
	K8sSvcCache            *k8s.ServiceCache
	CacheStatus            k8sSynced.CacheStatus
	K8sResourceSynced      *k8sSynced.Resources
	K8sAPIGroups           *k8sSynced.APIGroups
	NodeManager            nodeManager.NodeManager
	EndpointManager        endpointmanager.EndpointManager
	CertManager            certificatemanager.CertificateManager
	SecretManager          certificatemanager.SecretManager
	IdentityAllocator      CachingIdentityAllocator
	Policy                 *policy.Repository
	IPCache                *ipcache.IPCache
	DirectoryPolicyWatcher *policyDirectory.PolicyResourcesWatcher
	DirReadStatus          policyDirectory.DirectoryWatcherReadStatus
	CNIConfigManager       cni.CNIConfigManager
	SwaggerSpec            *server.Spec
	HealthAPISpec          *healthApi.Spec
	ServiceCache           *k8s.ServiceCache
	ClusterMesh            *clustermesh.ClusterMesh
	MonitorAgent           monitorAgent.Agent
	L2Announcer            *l2announcer.L2Announcer
	ServiceManager         service.ServiceManager
	L7Proxy                *proxy.Proxy
	EnvoyXdsServer         envoy.XDSServer
	DB                     *statedb.DB
	APILimiterSet          *rate.APILimiterSet
	AuthManager            *auth.AuthManager
	Settings               cellSettings
	Devices                statedb.Table[*datapathTables.Device]
	NodeAddrs              statedb.Table[datapathTables.NodeAddress]
	DirectRoutingDevice    datapathTables.DirectRoutingDevice
	// Grab the GC object so that we can start the CT/NAT map garbage collection.
	// This is currently necessary because these maps have not yet been modularized,
	// and because it depends on parameters which are not provided through hive.
	CTNATMapGC          gc.Enabler
	StoreFactory        store.Factory
	EndpointRegenerator *endpoint.Regenerator
	ClusterInfo         cmtypes.ClusterInfo
	BigTCPConfig        *bigtcp.Configuration
	TunnelConfig        tunnel.Config
	BandwidthManager    datapath.BandwidthManager
	IPsecKeyCustodian   datapath.IPsecKeyCustodian
	MTU                 mtu.MTU
	Sysctl              sysctl.Sysctl
	SyncHostIPs         *syncHostIPs
	NodeDiscovery       *nodediscovery.NodeDiscovery
	CompilationLock     datapath.CompilationLock
	MetalLBBgpSpeaker   speaker.MetalLBBgpSpeaker
	CGroupManager       cgroup.CGroupManager
	ServiceResolver     *dial.ServiceResolver
	Recorder            *recorder.Recorder
	IPAM                *ipam.IPAM
	CRDSyncPromise      promise.Promise[k8sSynced.CRDSync]
	IdentityManager     *identitymanager.IdentityManager
}

func newDaemonPromise(params daemonParams) (promise.Promise[*Daemon], promise.Promise[*option.DaemonConfig], promise.Promise[policyK8s.PolicyManager]) {
	daemonResolver, daemonPromise := promise.New[*Daemon]()
	cfgResolver, cfgPromise := promise.New[*option.DaemonConfig]()
	policyManagerResolver, policyManagerPromise := promise.New[policyK8s.PolicyManager]()

	// daemonCtx is the daemon-wide context cancelled when stopping.
	daemonCtx, cancelDaemonCtx := context.WithCancel(context.Background())
	cleaner := NewDaemonCleanup()

	if option.Config.LoadBalancerExternalControlPlane {
		params.Clientset.Disable()
	}

	var daemon *Daemon
	var wg sync.WaitGroup

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) (err error) {
			defer func() {
				// Reject promises on error
				if err != nil {
					cfgResolver.Reject(err)
					policyManagerResolver.Reject(err)
					daemonResolver.Reject(err)
				}
			}()

			d, restoredEndpoints, err := newDaemon(daemonCtx, cleaner, &params)
			if err != nil {
				cancelDaemonCtx()
				cleaner.Clean()
				return fmt.Errorf("daemon creation failed: %w", err)
			}
			daemon = d

			if !option.Config.DryMode {
				log.Info("Initializing daemon")

				// This validation needs to be done outside of the agent until
				// datapath.NodeAddressing is used consistently across the code base.
				log.Info("Validating configured node address ranges")
				if err := node.ValidatePostInit(); err != nil {
					return fmt.Errorf("postinit failed: %w", err)
				}

				// Store config in file before resolving the DaemonConfig promise.
				err = option.Config.StoreInFile(option.Config.StateDir)
				if err != nil {
					log.WithError(err).Error("Unable to store Cilium's configuration")
				}

				err = option.StoreViperInFile(option.Config.StateDir)
				if err != nil {
					log.WithError(err).Error("Unable to store Viper's configuration")
				}
			}

			// 'option.Config' is assumed to be stable at this point, execpt for
			// 'option.Config.Opts' that are explicitly deemed to be runtime-changeable
			cfgResolver.Resolve(option.Config)
			policyManagerResolver.Resolve(daemon)

			if option.Config.DryMode {
				daemonResolver.Resolve(daemon)
			} else {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := startDaemon(daemon, restoredEndpoints, cleaner, params); err != nil {
						log.WithError(err).Error("Daemon start failed")
						daemonResolver.Reject(err)
					} else {
						daemonResolver.Resolve(daemon)
					}
				}()
			}
			return nil
		},
		OnStop: func(cell.HookContext) error {
			cancelDaemonCtx()
			cleaner.Clean()
			wg.Wait()
			return nil
		},
	})
	return daemonPromise, cfgPromise, policyManagerPromise
}

// startDaemon starts the old unmodular part of the cilium-agent.
// option.Config has already been exposed via *option.DaemonConfig promise,
// so it may not be modified here
func startDaemon(d *Daemon, restoredEndpoints *endpointRestoreState, cleaner *daemonCleanup, params daemonParams) error {
	bootstrapStats.k8sInit.Start()
	if params.Clientset.IsEnabled() {
		// Wait only for certain caches, but not all!
		// (Check Daemon.InitK8sSubsystem() for more info)
		select {
		case <-params.CacheStatus:
		case <-d.ctx.Done():
			return d.ctx.Err()
		}
	}

	// wait for directory watcher to ingest policy from files
	<-params.DirReadStatus

	bootstrapStats.k8sInit.End(true)

	// After K8s caches have been synced, IPCache can start label injection.
	// Ensure that the initial labels are injected before we regenerate endpoints
	log.Debug("Waiting for initial IPCache revision")
	if err := d.ipcache.WaitForRevision(d.ctx, 1); err != nil {
		log.WithError(err).Error("Failed to wait for initial IPCache revision")
	}

	d.initRestore(restoredEndpoints, params.EndpointRegenerator)

	bootstrapStats.enableConntrack.Start()
	log.Info("Starting connection tracking garbage collector")
	params.CTNATMapGC.Enable()
	bootstrapStats.enableConntrack.End(true)

	if params.WGAgent != nil {
		go func() {
			if err := params.WGAgent.RestoreFinished(d.clustermesh); err != nil {
				log.WithError(err).Error("Failed to set up WireGuard peers")
			}
		}()
	}

	if d.endpointManager.HostEndpointExists() {
		d.endpointManager.InitHostEndpointLabels(d.ctx)
	} else {
		log.Info("Creating host endpoint")
		err := d.endpointManager.AddHostEndpoint(
			d.ctx, d, d, d.ipcache, d.l7Proxy, d.identityAllocator)
		if err != nil {
			return fmt.Errorf("unable to create host endpoint: %w", err)
		}
	}

	if option.Config.EnableEnvoyConfig {
		if !d.endpointManager.IngressEndpointExists() {
			// Creating Ingress Endpoint depends on the Ingress IPs having been
			// allocated first. This happens earlier in the agent bootstrap.
			if (option.Config.EnableIPv4 && len(node.GetIngressIPv4()) == 0) ||
				(option.Config.EnableIPv6 && len(node.GetIngressIPv6()) == 0) {
				log.Warn("Ingress IPs are not available, skipping creation of the Ingress Endpoint: Policy enforcement on Cilium Ingress will not work as expected.")
			} else {
				log.Info("Creating ingress endpoint")
				err := d.endpointManager.AddIngressEndpoint(
					d.ctx, d, d, d.ipcache, d.l7Proxy, d.identityAllocator)
				if err != nil {
					return fmt.Errorf("unable to create ingress endpoint: %w", err)
				}
			}
		}
	}

	if option.Config.EnableIPMasqAgent {
		ipmasqAgent, err := ipmasq.NewIPMasqAgent(option.Config.IPMasqAgentConfigPath)
		if err != nil {
			return fmt.Errorf("failed to create ipmasq agent: %w", err)
		}
		ipmasqAgent.Start()
	}

	go func() {
		if d.endpointRestoreComplete != nil {
			select {
			case <-d.endpointRestoreComplete:
			case <-d.ctx.Done():
				return
			}
		}
		d.dnsNameManager.CompleteBootstrap()

		ms := maps.NewMapSweeper(&EndpointMapManager{
			EndpointManager: d.endpointManager,
		}, d.bwManager)
		ms.CollectStaleMapGarbage()
		ms.RemoveDisabledMaps()

		// Sleep for the --identity-restore-grace-period (default: 30 seconds k8s, 10 minutes kvstore), allowing
		// the normal allocation processes to finish, before releasing restored resources.
		time.Sleep(option.Config.IdentityRestoreGracePeriod)
		d.releaseRestoredIdentities()
	}()
	d.endpointManager.Subscribe(d)
	// Add the endpoint manager unsubscribe as the last step in cleanup
	defer cleaner.cleanupFuncs.Add(func() { d.endpointManager.Unsubscribe(d) })

	// Migrating the ENI datapath must happen before the API is served to
	// prevent endpoints from being created. It also must be before the health
	// initialization logic which creates the health endpoint, for the same
	// reasons as the API being served. We want to ensure that this migration
	// logic runs before any endpoint creates.
	if option.Config.IPAM == ipamOption.IPAMENI {
		migrated, failed := linuxrouting.NewMigrator(
			&eni.InterfaceDB{Clientset: params.Clientset},
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
		d.initHealth(params.HealthAPISpec, cleaner, params.Sysctl)
	}
	bootstrapStats.healthCheck.End(true)

	d.startStatusCollector(cleaner)

	d.startAgentHealthHTTPService()
	if option.Config.KubeProxyReplacementHealthzBindAddr != "" {
		if option.Config.KubeProxyReplacement != option.KubeProxyReplacementFalse {
			d.startKubeProxyHealthzHTTPService(option.Config.KubeProxyReplacementHealthzBindAddr)
		}
	}

	err := d.SendNotification(monitorAPI.StartMessage(time.Now()))
	if err != nil {
		log.WithError(err).Warn("Failed to send agent start monitor message")
	}

	// Watches for node neighbors link updates.
	d.nodeDiscovery.Manager.StartNodeNeighborLinkUpdater(d.datapath.NodeNeighbors())

	if option.Config.DatapathMode != datapathOption.DatapathModeLBOnly {
		if !d.datapath.NodeNeighbors().NodeNeighDiscoveryEnabled() {
			// Remove all non-GC'ed neighbor entries that might have previously set
			// by a Cilium instance.
			d.datapath.NodeNeighbors().NodeCleanNeighbors(false)
		} else {
			// If we came from an agent upgrade, migrate entries.
			d.datapath.NodeNeighbors().NodeCleanNeighbors(true)
			// Start periodical refresh of the neighbor table from the agent if needed.
			if option.Config.ARPPingRefreshPeriod != 0 && !option.Config.ARPPingKernelManaged {
				d.nodeDiscovery.Manager.StartNeighborRefresh(d.datapath.NodeNeighbors())
			}
		}
	}

	log.WithField("bootstrapTime", time.Since(bootstrapTimestamp)).
		Info("Daemon initialization completed")

	bootstrapStats.overall.End(true)
	bootstrapStats.updateMetrics()
	go d.launchHubble()

	// Start controller to validate daemon config is unchanged
	cfgGroup := controller.NewGroup("daemon-validate-config")
	d.controllers.UpdateController(
		cfgGroup.Name,
		controller.ControllerParams{
			Group:  cfgGroup,
			Health: params.Health,
			DoFunc: func(context.Context) error {
				// Validate that Daemon config has not changed, ignoring 'Opts'
				// that may be modified via config patch events.
				return option.Config.ValidateUnchanged()
			},
			// avoid synhronized run with other
			// controllers started at same time
			RunInterval: 61 * time.Second,
			Context:     d.ctx,
		})

	return nil
}

func registerEndpointStateResolver(lc cell.Lifecycle, daemonPromise promise.Promise[*Daemon], resolver promise.Resolver[endpointstate.Restorer]) {
	var wg sync.WaitGroup

	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			wg.Add(1)
			go func() {
				defer wg.Done()
				daemon, err := daemonPromise.Await(context.Background())
				if err != nil {
					resolver.Reject(err)
				} else {
					resolver.Resolve(daemon)
				}
			}()
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			wg.Wait()
			return nil
		},
	})
}

func initClockSourceOption() {
	option.Config.ClockSource = option.ClockSourceKtime
	option.Config.KernelHz = 1 // Known invalid non-zero to avoid div by zero.
	hz, err := probes.KernelHZ()
	if err != nil {
		log.WithError(err).Infof("Auto-disabling %q feature since KERNEL_HZ cannot be determined", option.EnableBPFClockProbe)
		option.Config.EnableBPFClockProbe = false
	} else {
		option.Config.KernelHz = int(hz)
	}

	if option.Config.EnableBPFClockProbe {
		if probes.HaveProgramHelper(ebpf.XDP, asm.FnJiffies64) == nil {
			t, err := probes.Jiffies()
			if err == nil && t > 0 {
				option.Config.ClockSource = option.ClockSourceJiffies
			} else {
				log.WithError(err).Warningf("Auto-disabling %q feature since kernel doesn't expose jiffies", option.EnableBPFClockProbe)
				option.Config.EnableBPFClockProbe = false
			}
		} else {
			log.WithError(err).Warningf("Auto-disabling %q feature since kernel support is missing (Linux 5.5 or later required).", option.EnableBPFClockProbe)
			option.Config.EnableBPFClockProbe = false
		}
	}
}
