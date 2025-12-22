// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/daemon/cmd/legacy"
	"github.com/cilium/cilium/daemon/infraendpoints"
	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/kpr"
	kprinitializer "github.com/cilium/cilium/pkg/kpr/initializer"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/loadinfo"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/neighborsmap"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

const (
	// list of supported verbose debug groups
	argDebugVerboseFlow     = "flow"
	argDebugVerboseKvstore  = "kvstore"
	argDebugVerboseEnvoy    = "envoy"
	argDebugVerboseDatapath = "datapath"
	argDebugVerbosePolicy   = "policy"
	argDebugVerboseTagged   = "tagged"

	apiTimeout   = 60 * time.Second
	daemonSubsys = "daemon"

	// fatalSleep is the duration Cilium should sleep before existing in case
	// of a log.Fatal is issued or a CLI flag is specified but does not exist.
	fatalSleep = 2 * time.Second
)

var (
	bootstrapTimestamp = time.Now()
	bootstrapStats     = bootstrapStatistics{}
)

func InitGlobalFlags(logger *slog.Logger, cmd *cobra.Command, vp *viper.Viper) {
	flags := cmd.Flags()

	// Validators
	option.Config.FixedIdentityMappingValidator = option.Validator(func(val string) error {
		vals := strings.Split(val, "=")
		if len(vals) != 2 {
			return fmt.Errorf(`invalid fixed identity: expecting "<numeric-identity>=<identity-name>" got %q`, val)
		}
		ni, err := identity.ParseNumericIdentity(vals[0])
		if err != nil {
			return fmt.Errorf(`invalid numeric identity %q: %w`, val, err)
		}
		if !identity.IsUserReservedIdentity(ni) {
			return fmt.Errorf(`invalid numeric identity %q: valid numeric identity is between %d and %d`,
				val, identity.UserReservedNumericIdentity.Uint32(), identity.MinimalNumericIdentity.Uint32())
		}
		lblStr := vals[1]
		lbl := labels.ParseLabel(lblStr)
		if lbl.IsReservedSource() {
			return fmt.Errorf(`invalid source %q for label: %s`, labels.LabelSourceReserved, lblStr)
		}
		return nil
	})

	option.Config.BPFMapEventBuffersValidator = option.Validator(func(val string) error {
		vals := strings.Split(val, "=")
		if len(vals) != 2 {
			return fmt.Errorf(`invalid bpf map event config: expecting "<map_name>=<enabled>_<max_size>_<ttl>" got %q`, val)
		}
		_, err := option.ParseEventBufferTupleString(vals[1])
		if err != nil {
			return err
		}
		return nil
	})

	option.Config.FixedZoneMappingValidator = option.Validator(func(val string) error {
		vals := strings.Split(val, "=")
		if len(vals) != 2 {
			return fmt.Errorf(`invalid fixed zone: expecting "<zone-name>=<numeric-id>" got %q`, val)
		}
		lblStr := vals[0]
		if len(lblStr) == 0 {
			return fmt.Errorf(`invalid label: %q`, lblStr)
		}
		ni, err := strconv.Atoi(vals[1])
		if err != nil {
			return fmt.Errorf(`invalid numeric ID %q: %w`, vals[1], err)
		}
		if min, max := 1, math.MaxUint8; ni < min || ni >= max {
			return fmt.Errorf(`invalid numeric ID %q: valid numeric ID is between %d and %d`, vals[1], min, max)
		}
		return nil
	})

	// Env bindings

	hive.RegisterFlags(vp, flags)

	flags.Int(option.ClusterHealthPort, defaults.ClusterHealthPort, "TCP port for cluster-wide network connectivity health API")
	option.BindEnv(vp, option.ClusterHealthPort)

	flags.Bool(option.AllowICMPFragNeeded, defaults.AllowICMPFragNeeded, "Allow ICMP Fragmentation Needed type packets for purposes like TCP Path MTU.")
	option.BindEnv(vp, option.AllowICMPFragNeeded)

	flags.String(option.AllowLocalhost, option.AllowLocalhostAuto, "Policy when to allow local stack to reach local endpoints { auto | always | policy }")
	option.BindEnv(vp, option.AllowLocalhost)

	flags.Bool(option.AnnotateK8sNode, defaults.AnnotateK8sNode, "Annotate Kubernetes node")
	option.BindEnv(vp, option.AnnotateK8sNode)

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

	flags.String(option.ConfigFile, "", `Configuration file (default "$HOME/ciliumd.yaml")`)
	option.BindEnv(vp, option.ConfigFile)

	flags.String(option.ConfigDir, "", `Configuration directory that contains a file for each option`)
	option.BindEnv(vp, option.ConfigDir)

	flags.BoolP(option.DebugArg, "D", false, "Enable debugging mode")
	option.BindEnv(vp, option.DebugArg)

	flags.StringSlice(option.DebugVerbose, []string{}, "List of enabled verbose debug groups")
	option.BindEnv(vp, option.DebugVerbose)

	flags.String(option.DatapathMode, defaults.DatapathMode,
		fmt.Sprintf("Datapath mode name (%s, %s, %s, %s)",
			datapathOption.DatapathModeAuto, datapathOption.DatapathModeVeth,
			datapathOption.DatapathModeNetkit, datapathOption.DatapathModeNetkitL2))
	option.BindEnv(vp, option.DatapathMode)

	flags.Bool(option.EnableEndpointRoutes, defaults.EnableEndpointRoutes, "Use per endpoint routes instead of routing via cilium_host")
	option.BindEnv(vp, option.EnableEndpointRoutes)

	flags.Int(option.HealthCheckICMPFailureThreshold, defaults.HealthCheckICMPFailureThreshold, "Number of ICMP requests sent for each run of the health checker. If at least one ICMP response is received, the node or endpoint is marked as healthy.")
	option.BindEnv(vp, option.HealthCheckICMPFailureThreshold)

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

	flags.Var(option.NewMapOptions(&option.Config.IPAMMultiPoolPreAllocation),
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

	flags.StringSlice(option.MasqueradeInterfaces, []string{}, "Limit iptables-based egress masquerading to interfaces selector")
	option.BindEnv(vp, option.MasqueradeInterfaces)

	flags.Bool(option.BPFSocketLBHostnsOnly, false, "Skip socket LB for services when inside a pod namespace, in favor of service LB at the pod interface. Socket LB is still used when in the host namespace. Required by service mesh (e.g., Istio, Linkerd).")
	option.BindEnv(vp, option.BPFSocketLBHostnsOnly)

	flags.Bool(option.EnableSocketLBPodConnectionTermination, true, "Enable terminating connections to deleted service backends when socket-LB is enabled")
	flags.MarkHidden(option.EnableSocketLBPodConnectionTermination)
	option.BindEnv(vp, option.EnableSocketLBPodConnectionTermination)

	flags.Bool(option.EnableSocketLBTracing, true, "Enable tracing for socket-based LB")
	option.BindEnv(vp, option.EnableSocketLBTracing)

	flags.Bool(option.EnableAutoDirectRoutingName, defaults.EnableAutoDirectRouting, "Enable automatic L2 routing between nodes")
	option.BindEnv(vp, option.EnableAutoDirectRoutingName)

	flags.Bool(option.DirectRoutingSkipUnreachableName, defaults.EnableDirectRoutingSkipUnreachable, "Enable skipping L2 routes between nodes on different subnets")
	option.BindEnv(vp, option.DirectRoutingSkipUnreachableName)

	flags.Bool(option.EnableBPFTProxy, defaults.EnableBPFTProxy, "Enable BPF-based proxy redirection (beta), if support available")
	option.BindEnv(vp, option.EnableBPFTProxy)

	flags.Bool(option.EnableHostLegacyRouting, defaults.EnableHostLegacyRouting, "Enable the legacy host forwarding model which does not bypass upper stack in host namespace")
	option.BindEnv(vp, option.EnableHostLegacyRouting)

	flags.String(option.EnablePolicy, option.DefaultEnforcement, "Enable policy enforcement")
	option.BindEnv(vp, option.EnablePolicy)

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

	flags.Bool(option.BPFDistributedLRU, defaults.BPFDistributedLRU, "Enable per-CPU BPF LRU backend memory")
	option.BindEnv(vp, option.BPFDistributedLRU)

	flags.Bool(option.BPFConntrackAccounting, defaults.BPFConntrackAccounting, "Enable CT accounting for packets and bytes (default false)")
	option.BindEnv(vp, option.BPFConntrackAccounting)

	flags.Bool(option.EnableUnreachableRoutes, false, "Add unreachable routes on pod deletion")
	option.BindEnv(vp, option.EnableUnreachableRoutes)

	flags.Bool(option.EnableL2Announcements, false, "Enable L2 announcements")
	option.BindEnv(vp, option.EnableL2Announcements)

	flags.Duration(option.L2AnnouncerLeaseDuration, 15*time.Second, "Duration of inactivity after which a new leader is selected")
	option.BindEnv(vp, option.L2AnnouncerLeaseDuration)

	flags.Duration(option.L2AnnouncerRenewDeadline, 5*time.Second, "Interval at which the leader renews a lease")
	option.BindEnv(vp, option.L2AnnouncerRenewDeadline)

	flags.Duration(option.L2AnnouncerRetryPeriod, 2*time.Second, "Timeout after a renew failure, before the next retry")
	option.BindEnv(vp, option.L2AnnouncerRetryPeriod)

	flags.Bool(option.EnableEncryptionStrictMode, false, "Enable encryption strict mode")
	flags.MarkDeprecated(option.EnableEncryptionStrictMode, "Please use --enable-encryption-strict-mode-egress instead. This option will be removed in v1.20")
	option.BindEnv(vp, option.EnableEncryptionStrictMode)

	flags.String(option.EncryptionStrictModeCIDR, "", "In strict-mode encryption, all unencrypted traffic coming from this CIDR and going to this same CIDR will be dropped.")
	flags.MarkDeprecated(option.EncryptionStrictModeCIDR, "Please use --encryption-strict-egress-cidr instead. This option will be removed in v1.20")
	option.BindEnv(vp, option.EncryptionStrictModeCIDR)

	flags.Bool(option.EncryptionStrictModeAllowRemoteNodeIdentities, false, "Allows unencrypted traffic from pods to remote node identities within the strict mode CIDR. This is required when tunneling is used or direct routing is used and the node CIDR and pod CIDR overlap.")
	flags.MarkDeprecated(option.EncryptionStrictModeAllowRemoteNodeIdentities, "Please use --encryption-strict-egress-allow-remote-node-identities instead. This option will be removed in v1.20")
	option.BindEnv(vp, option.EncryptionStrictModeAllowRemoteNodeIdentities)

	flags.Bool(option.EnableEncryptionStrictModeEgress, false, "Enable strict mode encryption enforcement for egress traffic")
	option.BindEnv(vp, option.EnableEncryptionStrictModeEgress)

	flags.String(option.EncryptionStrictEgressCIDR, "", "In strict-mode-egress encryption, all unencrypted traffic coming from this CIDR and going to this same CIDR will be dropped.")
	option.BindEnv(vp, option.EncryptionStrictEgressCIDR)

	flags.Bool(option.EncryptionStrictEgressAllowRemoteNodeIdentities, false, "Allows unencrypted traffic from pods to remote node identities within the strict mode CIDR. This is required when tunneling is used or direct routing is used and the node CIDR and pod CIDR overlap.")
	option.BindEnv(vp, option.EncryptionStrictEgressAllowRemoteNodeIdentities)

	flags.Bool(option.EnableEncryptionStrictModeIngress, false, "Enable strict mode encryption enforcement for ingress traffic")
	option.BindEnv(vp, option.EnableEncryptionStrictModeIngress)

	flags.Var(option.NewMapOptions(&option.Config.FixedIdentityMapping, option.Config.FixedIdentityMappingValidator),
		option.FixedIdentityMapping, "Key-value for the fixed identity mapping which allows to use reserved label for fixed identities, e.g. 128=kv-store,129=kube-dns")
	option.BindEnv(vp, option.FixedIdentityMapping)

	flags.Duration(option.IdentityChangeGracePeriod, defaults.IdentityChangeGracePeriod, "Time to wait before using new identity on endpoint identity change")
	option.BindEnv(vp, option.IdentityChangeGracePeriod)

	flags.Duration(option.CiliumIdentityMaxJitter, defaults.CiliumIdentityMaxJitter, "Maximum jitter time to begin processing CiliumIdentity updates")
	option.BindEnv(vp, option.CiliumIdentityMaxJitter)

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

	flags.Bool(option.K8sRequireIPv4PodCIDRName, false, "Require IPv4 PodCIDR to be specified in node resource")
	option.BindEnv(vp, option.K8sRequireIPv4PodCIDRName)

	flags.Bool(option.K8sRequireIPv6PodCIDRName, false, "Require IPv6 PodCIDR to be specified in node resource")
	option.BindEnv(vp, option.K8sRequireIPv6PodCIDRName)

	flags.Bool(option.KeepConfig, false, "When restoring state, keeps containers' configuration in place")
	option.BindEnv(vp, option.KeepConfig)

	flags.Duration(option.K8sSyncTimeoutName, defaults.K8sSyncTimeout, "Timeout after last K8s event for synchronizing k8s resources before exiting")
	flags.MarkHidden(option.K8sSyncTimeoutName)
	option.BindEnv(vp, option.K8sSyncTimeoutName)

	flags.Duration(option.AllocatorListTimeoutName, defaults.AllocatorListTimeout, "Timeout for listing allocator state before exiting")
	option.BindEnv(vp, option.AllocatorListTimeoutName)

	flags.String(option.LabelPrefixFile, "", "Valid label prefixes file path")
	option.BindEnv(vp, option.LabelPrefixFile)

	flags.StringSlice(option.Labels, []string{}, "List of label prefixes used to determine identity of an endpoint")
	option.BindEnv(vp, option.Labels)

	flags.String(option.AddressScopeMax, fmt.Sprintf("%d", defaults.AddressScopeMax), "Maximum local address scope for ipcache to consider host addresses")
	flags.MarkHidden(option.AddressScopeMax)
	option.BindEnv(vp, option.AddressScopeMax)

	flags.Bool(option.EnableLocalRedirectPolicy, false, "Enable Local Redirect Policy")
	option.BindEnv(vp, option.EnableLocalRedirectPolicy)

	flags.Bool(option.EnableMKE, false, "Enable BPF kube-proxy replacement for MKE environments")
	flags.MarkHidden(option.EnableMKE)
	option.BindEnv(vp, option.EnableMKE)

	flags.String(option.CgroupPathMKE, "", "Cgroup v1 net_cls mount path for MKE environments")
	flags.MarkHidden(option.CgroupPathMKE)
	option.BindEnv(vp, option.CgroupPathMKE)

	flags.String(option.NodePortAcceleration, option.NodePortAccelerationDisabled, fmt.Sprintf(
		"BPF NodePort acceleration via XDP (\"%s\", \"%s\")",
		option.NodePortAccelerationNative, option.NodePortAccelerationDisabled))
	flags.MarkHidden(option.NodePortAcceleration)
	option.BindEnv(vp, option.NodePortAcceleration)

	flags.Bool(option.LoadBalancerNat46X64, false, "BPF load balancing support for NAT46 and NAT64")
	flags.MarkHidden(option.LoadBalancerNat46X64)
	option.BindEnv(vp, option.LoadBalancerNat46X64)

	flags.String(option.LoadBalancerRSSv4CIDR, "", "BPF load balancing RSS outer source IPv4 CIDR prefix for IPIP")
	option.BindEnv(vp, option.LoadBalancerRSSv4CIDR)

	flags.String(option.LoadBalancerRSSv6CIDR, "", "BPF load balancing RSS outer source IPv6 CIDR prefix for IPIP")
	option.BindEnv(vp, option.LoadBalancerRSSv6CIDR)

	flags.Bool(option.LoadBalancerIPIPSockMark, false, "BPF load balancing logic to force socket marked traffic via IPIP")
	flags.MarkHidden(option.LoadBalancerIPIPSockMark)
	option.BindEnv(vp, option.LoadBalancerIPIPSockMark)

	flags.String(option.LoadBalancerAcceleration, option.NodePortAccelerationDisabled, fmt.Sprintf(
		"BPF load balancing acceleration via XDP (\"%s\", \"%s\")",
		option.NodePortAccelerationNative, option.NodePortAccelerationDisabled))
	option.BindEnv(vp, option.LoadBalancerAcceleration)

	flags.Bool(option.EnableAutoProtectNodePortRange, true,
		"Append NodePort range to net.ipv4.ip_local_reserved_ports if it overlaps "+
			"with ephemeral port range (net.ipv4.ip_local_port_range)")
	option.BindEnv(vp, option.EnableAutoProtectNodePortRange)

	flags.Bool(option.NodePortBindProtection, true, "Reject application bind(2) requests to service ports in the NodePort range")
	option.BindEnv(vp, option.NodePortBindProtection)

	flags.Bool(option.EnableIdentityMark, true, "Enable setting identity mark for local traffic")
	option.BindEnv(vp, option.EnableIdentityMark)

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

	flags.Var(option.NewMapOptions(&option.Config.LogOpt),
		option.LogOpt, `Log driver options for cilium-agent, `+
			`configmap example for syslog driver: {"syslog.level":"info","syslog.facility":"local5","syslog.tag":"cilium-agent"}`)
	option.BindEnv(vp, option.LogOpt)

	flags.Bool(option.LogSystemLoadConfigName, false, "Enable periodic logging of system load")
	option.BindEnv(vp, option.LogSystemLoadConfigName)

	flags.Bool(option.EnableIPv4Masquerade, true, "Masquerade IPv4 traffic from endpoints leaving the host")
	option.BindEnv(vp, option.EnableIPv4Masquerade)

	flags.Bool(option.EnableRemoteNodeMasquerade, false, "Masquerade packets from endpoints leaving the host destined to a remote node in BPF masquerading mode. This option requires to set enable-bpf-masquerade to true.")
	option.BindEnv(vp, option.EnableRemoteNodeMasquerade)

	flags.Bool(option.EnableIPv6Masquerade, true, "Masquerade IPv6 traffic from endpoints leaving the host")
	option.BindEnv(vp, option.EnableIPv6Masquerade)

	flags.Bool(option.EnableBPFMasquerade, false, "Masquerade packets from endpoints leaving the host with BPF instead of iptables")
	option.BindEnv(vp, option.EnableBPFMasquerade)

	flags.Bool(option.EnableMasqueradeRouteSource, false, "Masquerade packets to the source IP provided from the routing layer rather than interface address")
	option.BindEnv(vp, option.EnableMasqueradeRouteSource)

	flags.Bool(option.EnableEgressGateway, false, "Enable egress gateway")
	option.BindEnv(vp, option.EnableEgressGateway)

	flags.Bool(option.EnableEnvoyConfig, false, "Enable Envoy Config CRDs")
	option.BindEnv(vp, option.EnableEnvoyConfig)

	flags.Bool(option.InstallIptRules, true, "Install base iptables rules for cilium to mainly interact with kube-proxy (and masquerading)")
	flags.MarkHidden(option.InstallIptRules)
	option.BindEnv(vp, option.InstallIptRules)

	flags.Uint(option.MaxCtrlIntervalName, 0, "Maximum interval (in seconds) between controller runs. Zero is no limit.")
	flags.MarkHidden(option.MaxCtrlIntervalName)
	option.BindEnv(vp, option.MaxCtrlIntervalName)

	flags.String(option.MonitorAggregationName, "None",
		"Level of monitor aggregation for traces from the datapath")
	option.BindEnvWithLegacyEnvFallback(vp, option.MonitorAggregationName, "CILIUM_MONITOR_AGGREGATION_LEVEL")

	flags.Int(option.RouteMetric, 0, "Overwrite the metric used by cilium when adding routes to its 'cilium_host' device")
	option.BindEnv(vp, option.RouteMetric)

	flags.String(option.IPv6NodeAddr, "auto", "IPv6 address of node")
	option.BindEnv(vp, option.IPv6NodeAddr)

	flags.String(option.IPv4NodeAddr, "auto", "IPv4 address of node")
	option.BindEnv(vp, option.IPv4NodeAddr)

	flags.Bool(option.Restore, true, "Restores state, if possible, from previous daemon")
	flags.MarkHidden(option.Restore)
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

	flags.Int(option.TracePayloadlen, defaults.TracePayloadLen, "Length of payload to capture when tracing native packets.")

	flags.String(option.PolicyDenyResponse, defaults.PolicyDenyResponse, "How to handle pod egress traffic dropped by network policy: either drop the packet (\"none\") or reject with an ICMP Destination Unreachable (\"icmp\")")
	option.BindEnv(vp, option.PolicyDenyResponse)

	option.BindEnv(vp, option.TracePayloadlen)

	flags.Int(option.TracePayloadlenOverlay, defaults.TracePayloadLenOverlay, "Length of payload to capture when tracing overlay packets.")
	option.BindEnv(vp, option.TracePayloadlenOverlay)

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

	flags.Duration(option.PolicyMapFullReconciliationIntervalName, 15*time.Minute, "Interval for full reconciliation of endpoint policy map")
	option.BindEnv(vp, option.PolicyMapFullReconciliationIntervalName)
	flags.MarkHidden(option.PolicyMapFullReconciliationIntervalName)

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

	flags.Bool(option.DNSPolicyUnloadOnShutdown, false, "Unload DNS policy rules on graceful shutdown")
	option.BindEnv(vp, option.DNSPolicyUnloadOnShutdown)

	flags.Int(option.ToFQDNsMaxDeferredConnectionDeletes, defaults.ToFQDNsMaxDeferredConnectionDeletes, "Maximum number of IPs to retain for expired DNS lookups with still-active connections")
	option.BindEnv(vp, option.ToFQDNsMaxDeferredConnectionDeletes)

	flags.Duration(option.ToFQDNsIdleConnectionGracePeriod, defaults.ToFQDNsIdleConnectionGracePeriod, "Time during which idle but previously active connections with expired DNS lookups are still considered alive (default 0s)")
	option.BindEnv(vp, option.ToFQDNsIdleConnectionGracePeriod)

	flags.Duration(option.FQDNProxyResponseMaxDelay, defaults.FQDNProxyResponseMaxDelay, "The maximum time the DNS proxy holds an allowed DNS response before sending it along. Responses are sent as soon as the datapath is updated with the new IP information.")
	option.BindEnv(vp, option.FQDNProxyResponseMaxDelay)

	flags.Uint(option.FQDNRegexCompileLRUSize, defaults.FQDNRegexCompileLRUSize, "Size of the FQDN regex compilation LRU. Useful for heavy but repeated DNS L7 rules with MatchName or MatchPattern")
	flags.MarkHidden(option.FQDNRegexCompileLRUSize)
	option.BindEnv(vp, option.FQDNRegexCompileLRUSize)

	flags.String(option.ToFQDNsPreCache, defaults.ToFQDNsPreCache, "DNS cache data at this path is preloaded on agent startup")
	option.BindEnv(vp, option.ToFQDNsPreCache)

	flags.Int(option.DNSProxyConcurrencyLimit, 0, "Limit concurrency of DNS message processing")
	option.BindEnv(vp, option.DNSProxyConcurrencyLimit)

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

	flags.Int(option.EndpointQueueSize, defaults.EndpointQueueSize, "Size of EventQueue per-endpoint")
	option.BindEnv(vp, option.EndpointQueueSize)

	flags.Duration(option.PolicyTriggerInterval, defaults.PolicyTriggerInterval, "Time between triggers of policy updates (regenerations for all endpoints)")
	flags.MarkHidden(option.PolicyTriggerInterval)
	option.BindEnv(vp, option.PolicyTriggerInterval)

	flags.Bool(option.PolicyAuditModeArg, false, "Enable policy audit (non-drop) mode")
	option.BindEnv(vp, option.PolicyAuditModeArg)

	flags.Bool(option.PolicyAccountingArg, defaults.PolicyAccounting, "Maintain packet and byte counters for every policy entry")
	option.BindEnv(vp, option.PolicyAccountingArg)

	flags.Bool(option.EnableIPv4FragmentsTrackingName, defaults.EnableIPv4FragmentsTracking, "Enable IPv4 fragments tracking for L4-based lookups")
	option.BindEnv(vp, option.EnableIPv4FragmentsTrackingName)

	flags.Bool(option.EnableIPv6FragmentsTrackingName, defaults.EnableIPv6FragmentsTracking, "Enable IPv6 fragments tracking for L4-based lookups")
	option.BindEnv(vp, option.EnableIPv6FragmentsTrackingName)

	flags.Int(option.FragmentsMapEntriesName, defaults.FragmentsMapEntries, "Maximum number of entries in fragments tracking map")
	option.BindEnv(vp, option.FragmentsMapEntriesName)

	flags.Int(option.BPFEventsDefaultRateLimit, 0, fmt.Sprintf("Limit of average number of messages per second that can be written to BPF events map (if set, --%s value must also be specified). If both --%s and --%s are 0 or not specified, no limit is imposed.", option.BPFEventsDefaultBurstLimit, option.BPFEventsDefaultRateLimit, option.BPFEventsDefaultBurstLimit))
	flags.MarkHidden(option.BPFEventsDefaultRateLimit)
	option.BindEnv(vp, option.BPFEventsDefaultRateLimit)

	flags.Int(option.BPFEventsDefaultBurstLimit, 0, fmt.Sprintf("Maximum number of messages that can be written to BPF events map in 1 second (if set, --%s value must also be specified). If both --%s and --%s are 0 or not specified, no limit is imposed.", option.BPFEventsDefaultRateLimit, option.BPFEventsDefaultBurstLimit, option.BPFEventsDefaultRateLimit))
	flags.MarkHidden(option.BPFEventsDefaultBurstLimit)
	option.BindEnv(vp, option.BPFEventsDefaultBurstLimit)

	flags.String(option.LocalRouterIPv4, "", "Link-local IPv4 used for Cilium's router devices")
	option.BindEnv(vp, option.LocalRouterIPv4)

	flags.String(option.LocalRouterIPv6, "", "Link-local IPv6 used for Cilium's router devices")
	option.BindEnv(vp, option.LocalRouterIPv6)

	flags.Var(option.NewMapOptions(&option.Config.BPFMapEventBuffers, option.Config.BPFMapEventBuffersValidator), option.BPFMapEventBuffers, "Configuration for BPF map event buffers: (example: --bpf-map-event-buffers cilium_ipcache_v2=enabled_1024_1h)")
	flags.MarkHidden(option.BPFMapEventBuffers)

	flags.Bool(option.InstallUplinkRoutesForDelegatedIPAM, false,
		"Install ingress/egress routes through uplink on host for Pods when working with delegated IPAM plugin.")
	option.BindEnv(vp, option.InstallUplinkRoutesForDelegatedIPAM)

	flags.Bool(option.InstallNoConntrackIptRules, defaults.InstallNoConntrackIptRules, "Install Iptables rules to skip netfilter connection tracking on all pod traffic. This option is only effective when Cilium is running in direct routing and full KPR mode. Moreover, this option cannot be enabled when Cilium is running in a managed Kubernetes environment or in a chained CNI setup.")
	option.BindEnv(vp, option.InstallNoConntrackIptRules)

	flags.String(option.ContainerIPLocalReservedPorts, defaults.ContainerIPLocalReservedPortsAuto, "Instructs the Cilium CNI plugin to reserve the provided comma-separated list of ports in the container network namespace. "+
		"Prevents the container from using these ports as ephemeral source ports (see Linux ip_local_reserved_ports). Use this flag if you observe port conflicts between transparent DNS proxy requests and host network namespace services. "+
		"Value \"auto\" reserves the WireGuard and VXLAN ports used by Cilium")
	option.BindEnv(vp, option.ContainerIPLocalReservedPorts)

	// flags.IntSlice cannot be used due to missing support for appropriate conversion in Viper.
	// See https://github.com/cilium/cilium/pull/20282 for more information.
	flags.StringSlice(option.VLANBPFBypass, []string{}, "List of explicitly allowed VLAN IDs, '0' id will allow all VLAN IDs")
	option.BindEnv(vp, option.VLANBPFBypass)

	flags.Bool(option.DisableExternalIPMitigation, false, "Disable ExternalIP mitigation (CVE-2020-8554, default false)")
	option.BindEnv(vp, option.DisableExternalIPMitigation)

	flags.Bool(option.EnableICMPRules, defaults.EnableICMPRules, "Enable ICMP-based rule support for Cilium Network Policies")
	flags.MarkHidden(option.EnableICMPRules)
	option.BindEnv(vp, option.EnableICMPRules)

	flags.Bool(option.BypassIPAvailabilityUponRestore, false, "Bypasses the IP availability error within IPAM upon endpoint restore")
	flags.MarkHidden(option.BypassIPAvailabilityUponRestore)
	option.BindEnv(vp, option.BypassIPAvailabilityUponRestore)

	flags.Bool(option.EnableCiliumEndpointSlice, false, "Enable the CiliumEndpointSlice watcher in place of the CiliumEndpoint watcher (beta)")
	option.BindEnv(vp, option.EnableCiliumEndpointSlice)

	flags.Bool(option.EnableVTEP, defaults.EnableVTEP, "Enable  VXLAN Tunnel Endpoint (VTEP) Integration (beta)")
	option.BindEnv(vp, option.EnableVTEP)

	flags.String(option.VtepMask, "255.255.255.0", "VTEP CIDR Mask for all VTEP CIDRs")
	option.BindEnv(vp, option.VtepMask)

	flags.Int(option.TCFilterPriority, 1, "Priority of TC BPF filter")
	flags.MarkHidden(option.TCFilterPriority)
	option.BindEnv(vp, option.TCFilterPriority)

	flags.Bool(option.EnableBGPControlPlane, false, "Enable the BGP control plane.")
	option.BindEnv(vp, option.EnableBGPControlPlane)

	flags.Bool(option.EnableBGPControlPlaneStatusReport, true, "Enable the BGP control plane status reporting")
	option.BindEnv(vp, option.EnableBGPControlPlaneStatusReport)

	flags.String(option.BGPRouterIDAllocationMode, option.BGPRouterIDAllocationModeDefault, "BGP router-id allocation mode. Currently supported values: 'default' or 'ip-pool'")
	option.BindEnv(vp, option.BGPRouterIDAllocationMode)

	flags.String(option.BGPRouterIDAllocationIPPool, "", "IP pool to allocate the BGP router-id from when the mode is 'ip-pool'")
	option.BindEnv(vp, option.BGPRouterIDAllocationIPPool)

	flags.Bool(option.EnablePMTUDiscovery, false, "Enable path MTU discovery to send ICMP fragmentation-needed replies to the client")
	option.BindEnv(vp, option.EnablePMTUDiscovery)

	flags.Duration(option.IPAMCiliumNodeUpdateRate, 15*time.Second, "Maximum rate at which the CiliumNode custom resource is updated")
	option.BindEnv(vp, option.IPAMCiliumNodeUpdateRate)

	flags.Bool(option.EnableK8sNetworkPolicy, defaults.EnableK8sNetworkPolicy, "Enable support for K8s NetworkPolicy")
	flags.MarkHidden(option.EnableK8sNetworkPolicy)
	option.BindEnv(vp, option.EnableK8sNetworkPolicy)

	flags.Bool(option.EnableCiliumNetworkPolicy, defaults.EnableCiliumNetworkPolicy, "Enable support for Cilium Network Policy")
	flags.MarkHidden(option.EnableCiliumNetworkPolicy)
	option.BindEnv(vp, option.EnableCiliumNetworkPolicy)

	flags.Bool(option.EnableCiliumClusterwideNetworkPolicy, defaults.EnableCiliumClusterwideNetworkPolicy, "Enable support for Cilium Clusterwide Network Policy")
	flags.MarkHidden(option.EnableCiliumClusterwideNetworkPolicy)
	option.BindEnv(vp, option.EnableCiliumClusterwideNetworkPolicy)

	flags.StringSlice(option.PolicyCIDRMatchMode, defaults.PolicyCIDRMatchMode, "The entities that can be selected by CIDR policy. Supported values: 'nodes'")
	option.BindEnv(vp, option.PolicyCIDRMatchMode)

	flags.Duration(option.MaxInternalTimerDelay, defaults.MaxInternalTimerDelay, "Maximum internal timer value across the entire agent. Use in test environments to detect race conditions in agent logic.")
	flags.MarkHidden(option.MaxInternalTimerDelay)
	option.BindEnv(vp, option.MaxInternalTimerDelay)

	flags.Bool(option.EnableNodeSelectorLabels, defaults.EnableNodeSelectorLabels, "Enable use of node label based identity")
	option.BindEnv(vp, option.EnableNodeSelectorLabels)

	flags.StringSlice(option.NodeLabels, []string{}, "List of label prefixes used to determine identity of a node (used only when enable-node-selector-labels is enabled)")
	option.BindEnv(vp, option.NodeLabels)

	flags.Bool(option.EnableNonDefaultDenyPolicies, defaults.EnableNonDefaultDenyPolicies, "Enable use of non-default-deny policies")
	flags.MarkHidden(option.EnableNonDefaultDenyPolicies)
	option.BindEnv(vp, option.EnableNonDefaultDenyPolicies)

	flags.Bool(option.EnableEndpointLockdownOnPolicyOverflow, false, "When an endpoint's policy map overflows, shutdown all (ingress and egress) network traffic for that endpoint.")
	option.BindEnv(vp, option.EnableEndpointLockdownOnPolicyOverflow)

	flags.String(option.BootIDFilename, "/proc/sys/kernel/random/boot_id", "Path to filename of the boot ID")
	flags.MarkHidden(option.BootIDFilename)
	option.BindEnv(vp, option.BootIDFilename)

	flags.Float64(option.ConnectivityProbeFrequencyRatio, defaults.ConnectivityProbeFrequencyRatio, "Ratio of the connectivity probe frequency vs resource usage, a float in [0, 1]. 0 will give more frequent probing, 1 will give less frequent probing. Probing frequency is dynamically adjusted based on the cluster size.")
	option.BindEnv(vp, option.ConnectivityProbeFrequencyRatio)

	flags.Bool(option.EnableExtendedIPProtocols, defaults.EnableExtendedIPProtocols, "Enable traffic with extended IP protocols in datapath")
	option.BindEnv(vp, option.EnableExtendedIPProtocols)

	flags.Uint8(option.IPTracingOptionType, 0, "Specifies what IPv4 option type should be used to extract trace information from a packet; a value of 0 (default) disables IP tracing.")
	option.BindEnv(vp, option.IPTracingOptionType)

	flags.Bool(option.EnableCiliumNodeCRDName, defaults.EnableCiliumNodeCRD, "Enable use of CiliumNode CRD")
	flags.MarkHidden(option.EnableCiliumNodeCRDName)
	option.BindEnv(vp, option.EnableCiliumNodeCRDName)

	if err := vp.BindPFlags(flags); err != nil {
		logging.Fatal(logger, "BindPFlags failed", logfields.Error, err)
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
		if err := os.Chmod(fileToChange, os.FileMode(0o740)); err != nil {
			return err
		}
	}
	return err
}

func initDaemonConfigAndLogging(vp *viper.Viper) {
	option.Config.SetMapElementSizes(
		// for the conntrack and NAT element size we assume the largest possible
		// key size, i.e. IPv6 keys
		ctmap.SizeofCtKey6Global+ctmap.SizeofCtEntry,
		nat.SizeofNatKey6+nat.SizeofNatEntry6,
		neighborsmap.SizeofNeighKey6+neighborsmap.SizeOfNeighValue,
		lbmaps.SizeofSockRevNat6Key+lbmaps.SizeofSockRevNat6Value)

	option.Config.SetupLogging(vp, "cilium-agent")

	// slogloggercheck: using default logger for configuration initialization
	option.Config.Populate(logging.DefaultSlogLogger, vp)
	// slogloggercheck: using default logger for configuration initialization
	option.Config.PopulateEnableCiliumNodeCRD(logging.DefaultSlogLogger, vp)

	// add hooks after setting up metrics in the option.Config
	logging.AddHandlers(metrics.NewLoggingHook())

	time.MaxInternalTimerDelay = vp.GetDuration(option.MaxInternalTimerDelay)
}

func initEnv(logger *slog.Logger, vp *viper.Viper) {
	bootstrapStats.earlyInit.Start()
	defer bootstrapStats.earlyInit.End(true)

	var debugDatapath bool

	option.LogRegisteredSlogOptions(vp, logger)

	for _, grp := range option.Config.DebugVerbose {
		switch grp {
		case argDebugVerboseFlow:
			logger.Debug("Enabling flow debug")
			flowdebug.Enable()
		case argDebugVerboseKvstore:
			kvstore.EnableTracing()
		case argDebugVerboseEnvoy:
			logger.Debug("Enabling Envoy tracing")
			envoy.EnableTracing()
		case argDebugVerboseDatapath:
			logger.Debug("Enabling datapath debug messages")
			debugDatapath = true
		case argDebugVerbosePolicy:
			option.Config.Opts.SetBool(option.DebugPolicy, true)
		case argDebugVerboseTagged:
			option.Config.Opts.SetBool(option.DebugTagged, true)
		default:
			logger.Warn("Unknown verbose debug group", logfields.Group, grp)
		}
	}

	common.RequireRootPrivilege("cilium-agent")

	logger.Info("     _ _ _")
	logger.Info(" ___|_| |_|_ _ _____")
	logger.Info("|  _| | | | | |     |")
	logger.Info("|___|_|_|_|___|_|_|_|")
	logger.Info(fmt.Sprintf("Cilium %s", version.Version))

	if option.Config.LogSystemLoadConfig {
		loadinfo.StartBackgroundLogger(logger)
	}

	if option.Config.PreAllocateMaps {
		bpf.EnableMapPreAllocation()
	}
	if option.Config.BPFDistributedLRU {
		bpf.EnableMapDistributedLRU()
	}

	option.Config.BpfDir = filepath.Join(option.Config.LibDir, defaults.BpfDir)
	option.Config.StateDir = filepath.Join(option.Config.RunDir, defaults.StateDir)

	scopedLog := logger.With(
		logfields.RunDirectory, option.Config.RunDir,
		logfields.LibDirectory, option.Config.LibDir,
		logfields.BPFDirectory, option.Config.BpfDir,
		logfields.StateDirectory, option.Config.StateDir,
	)

	if err := os.MkdirAll(option.Config.RunDir, defaults.RuntimePathRights); err != nil {
		logging.Fatal(scopedLog, "Could not create runtime directory", logfields.Error, err)
	}

	if option.Config.RunDir != defaults.RuntimePath {
		if err := os.MkdirAll(defaults.RuntimePath, defaults.RuntimePathRights); err != nil {
			logging.Fatal(scopedLog, "Could not create default runtime directory", logfields.Error, err)
		}
	}

	if err := os.MkdirAll(option.Config.StateDir, defaults.StateDirRights); err != nil {
		logging.Fatal(scopedLog, "Could not create state directory", logfields.Error, err)
	}

	if err := os.MkdirAll(option.Config.LibDir, defaults.RuntimePathRights); err != nil {
		logging.Fatal(scopedLog, "Could not create library directory", logfields.Error, err)
	}
	// Restore permissions of executable files
	if err := restoreExecPermissions(option.Config.LibDir, `.*\.sh`); err != nil {
		logging.Fatal(scopedLog, "Unable to restore agent asset permissions", logfields.Error, err)
	}

	// Creating Envoy sockets directory for cases which doesn't provide a volume mount
	// (e.g. embedded Envoy, external workload in ClusterMesh scenario)
	if err := os.MkdirAll(envoy.GetSocketDir(option.Config.RunDir), defaults.RuntimePathRights); err != nil {
		logging.Fatal(scopedLog, "Could not create envoy sockets directory", logfields.Error, err)
	}

	// set rlimit Memlock to INFINITY before creating any bpf resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		logging.Fatal(scopedLog, "unable to set memory resource limits", logfields.Error, err)
	}

	globalsDir := option.Config.GetGlobalsDir()
	if err := os.MkdirAll(globalsDir, defaults.StateDirRights); err != nil {
		logging.Fatal(scopedLog, "Could not create runtime directory",
			logfields.Error, err,
			logfields.Path, globalsDir,
		)
	}
	if err := os.Chdir(option.Config.StateDir); err != nil {
		logging.Fatal(scopedLog, "Could not change to runtime directory",
			logfields.Error, err,
			logfields.Path, option.Config.StateDir,
		)
	}
	if _, err := os.Stat(option.Config.BpfDir); os.IsNotExist(err) {
		logging.Fatal(scopedLog, "BPF template directory: NOT OK. Please run 'make install-bpf'", logfields.Error, err)
	}

	if err := probes.CreateHeaderFiles(filepath.Join(option.Config.BpfDir, "include/bpf"), probes.ExecuteHeaderProbes(scopedLog)); err != nil {
		logging.Fatal(scopedLog, "failed to create header files with feature macros", logfields.Error, err)
	}

	if err := pidfile.Write(defaults.PidFilePath); err != nil {
		logging.Fatal(scopedLog, "Failed to create Pidfile",
			logfields.Error, err,
			logfields.Path, defaults.PidFilePath,
		)
	}

	option.Config.UnsafeDaemonConfigOption.AllowLocalhost = strings.ToLower(option.Config.UnsafeDaemonConfigOption.AllowLocalhost)
	switch option.Config.UnsafeDaemonConfigOption.AllowLocalhost {
	case option.AllowLocalhostAlways, option.AllowLocalhostAuto, option.AllowLocalhostPolicy:
	default:
		logging.Fatal(scopedLog, fmt.Sprintf("Invalid setting for --allow-localhost, must be { %s, %s, %s }",
			option.AllowLocalhostAuto, option.AllowLocalhostAlways, option.AllowLocalhostPolicy))
	}

	scopedLog = logger.With(logfields.Path, option.Config.SocketPath)
	socketDir := path.Dir(option.Config.SocketPath)
	if err := os.MkdirAll(socketDir, defaults.RuntimePathRights); err != nil {
		logging.Fatal(
			scopedLog,
			"Cannot mkdir directory for cilium socket",
			logfields.Error, err,
		)
	}

	if err := os.Remove(option.Config.SocketPath); !os.IsNotExist(err) && err != nil {
		logging.Fatal(
			scopedLog,
			"Cannot remove existing Cilium sock",
			logfields.Error, err,
		)
	}

	// The standard operation is to mount the BPF filesystem to the
	// standard location (/sys/fs/bpf). The user may choose to specify
	// the path to an already mounted filesystem instead. This is
	// useful if the daemon is being round inside a namespace and the
	// BPF filesystem is mapped into the slave namespace.
	bpf.CheckOrMountFS(logger, option.Config.BPFRoot)
	cgroups.CheckOrMountCgrpFS(logger, option.Config.CGroupRoot)

	option.Config.Opts.SetBool(option.Debug, debugDatapath)
	option.Config.Opts.SetBool(option.DebugLB, debugDatapath)
	option.Config.Opts.SetBool(option.DropNotify, option.Config.BPFEventsDropEnabled)
	option.Config.Opts.SetBool(option.PolicyVerdictNotify, option.Config.BPFEventsPolicyVerdictEnabled)
	option.Config.Opts.SetBool(option.TraceNotify, option.Config.BPFEventsTraceEnabled)
	option.Config.Opts.SetBool(option.PolicyTracing, option.Config.EnableTracing)
	option.Config.Opts.SetBool(option.PolicyAuditMode, option.Config.PolicyAuditMode)
	option.Config.Opts.SetBool(option.SourceIPVerification, option.Config.EnableSourceIPVerification)

	monitorAggregationLevel, err := option.ParseMonitorAggregationLevel(option.Config.MonitorAggregation)
	if err != nil {
		logging.Fatal(logger, fmt.Sprintf("Failed to parse %s", option.MonitorAggregationName), logfields.Error, err)
	}
	option.Config.Opts.SetValidated(option.MonitorAggregation, monitorAggregationLevel)

	policy.SetPolicyEnabled(option.Config.EnablePolicy)
	if option.Config.PolicyAuditMode {
		logger.Warn(fmt.Sprintf("%s is enabled. Network policy will not be enforced.", option.PolicyAuditMode))
	}

	if err := identity.AddUserDefinedNumericIdentitySet(option.Config.FixedIdentityMapping); err != nil {
		logging.Fatal(logger, "Invalid fixed identities provided", logfields.Error, err)
	}

	if !option.Config.EnableIPv4 && !option.Config.EnableIPv6 {
		logging.Fatal(logger, "Either IPv4 or IPv6 addressing must be enabled")
	}
	if err := labelsfilter.ParseLabelPrefixCfg(logger, option.Config.Labels, option.Config.NodeLabels, option.Config.LabelPrefixFile); err != nil {
		logging.Fatal(logger, "Unable to parse Label prefix configuration", logfields.Error, err)
	}

	if option.Config.EnableL7Proxy && !option.Config.InstallIptRules {
		logging.Fatal(logger, "L7 proxy requires iptables rules (--install-iptables-rules=\"true\")")
	}

	if option.Config.EnableRemoteNodeMasquerade && !option.Config.EnableBPFMasquerade {
		logging.Fatal(logger, "Option "+option.EnableRemoteNodeMasquerade+" requires BPF masquerade to be enabled ("+option.EnableBPFMasquerade+")")
	}

	if option.Config.TunnelingEnabled() && option.Config.EnableAutoDirectRouting {
		logging.Fatal(logger, fmt.Sprintf("%s cannot be used with tunneling. Packets must be routed through the tunnel device.", option.EnableAutoDirectRoutingName))
	}

	initClockSourceOption(logger)

	if option.Config.EnableSRv6 {
		if !option.Config.EnableIPv6 {
			logging.Fatal(logger, "SRv6 requires IPv6.")
		}
	}

	if option.Config.EnableIPv4FragmentsTracking {
		if !option.Config.EnableIPv4 {
			option.Config.EnableIPv4FragmentsTracking = false
		}
	}

	if option.Config.EnableIPv6FragmentsTracking {
		if !option.Config.EnableIPv6 {
			option.Config.EnableIPv6FragmentsTracking = false
		}
	}

	if option.Config.LocalRouterIPv4 != "" || option.Config.LocalRouterIPv6 != "" {
		// TODO(weil0ng): add a proper check for ipam in PR# 15429.
		if option.Config.TunnelingEnabled() {
			logging.Fatal(logger, fmt.Sprintf("Cannot specify %s or %s in tunnel mode.", option.LocalRouterIPv4, option.LocalRouterIPv6))
		}
		if !option.Config.EnableEndpointRoutes {
			logging.Fatal(logger, fmt.Sprintf("Cannot specify %s or %s  without %s.", option.LocalRouterIPv4, option.LocalRouterIPv6, option.EnableEndpointRoutes))
		}
	}

	if option.Config.EnableEndpointRoutes && option.Config.EnableLocalNodeRoute {
		option.Config.EnableLocalNodeRoute = false
		logger.Debug(
			"Auto-set option to `false` because it is redundant to per-endpoint routes",
			logfields.Option, option.EnableLocalNodeRoute,
			option.EnableEndpointRoutes, true,
		)
	}

	if option.Config.IPAM == ipamOption.IPAMENI && option.Config.TunnelingEnabled() {
		logging.Fatal(logger, fmt.Sprintf("Cannot specify IPAM mode %s in tunnel mode.", option.Config.IPAM))
	}

	if option.Config.InstallNoConntrackIptRules {
		// InstallNoConntrackIptRules can only be enabled in direct
		// routing mode as in tunneling mode the encapsulated traffic is
		// already skipping netfilter conntrack.
		if option.Config.TunnelingEnabled() {
			logging.Fatal(logger, fmt.Sprintf("%s requires the agent to run in direct routing mode.", option.InstallNoConntrackIptRules))
		}

		// Moreover InstallNoConntrackIptRules requires IPv4 support as
		// the native routing CIDR, used to select all pod traffic, can
		// only be an IPv4 CIDR at the moment.
		if !option.Config.EnableIPv4 {
			logging.Fatal(logger, fmt.Sprintf("%s requires IPv4 support.", option.InstallNoConntrackIptRules))
		}
	}

	// Ensure that the user does not turn on this mode unless it's for an IPAM
	// mode which support the bypass.
	if option.Config.BypassIPAvailabilityUponRestore {
		switch option.Config.IPAMMode() {
		case ipamOption.IPAMENI, ipamOption.IPAMAzure:
			logger.Info(
				"Running with bypass of IP not available errors upon endpoint " +
					"restore. Be advised that this mode is intended to be " +
					"temporary to ease upgrades. Consider restarting the pods " +
					"which have IPs not from the pool.",
			)
		default:
			option.Config.BypassIPAvailabilityUponRestore = false
			logger.Warn(
				fmt.Sprintf(
					"Bypassing IP allocation upon endpoint restore (%q) is enabled with"+
						"unintended IPAM modes. This bypass is only intended "+
						"to work for CRD-based IPAM modes such as ENI. Disabling "+
						"bypass.",
					option.BypassIPAvailabilityUponRestore,
				),
			)
		}
	}
}

// daemonCell wraps the existing implementation of the cilium-agent that has
// not yet been converted into a cell.
var daemonCell = cell.Module(
	"daemon",
	"Legacy Daemon",

	cell.Provide(daemonLegacyInitialization),
	cell.Invoke(func(_ legacy.DaemonInitialization) {}), // Force initialization.
)

// daemonConfigCell provides the DaemonConfig that contains properties
// that haven't yet been refactored to use module specific configs.
var daemonConfigCell = cell.Module(
	"daemonconfig",
	"Provides and initializes global DaemonConfig",

	cell.Provide(
		// Initialize unsafe daemonconfig properties that depend on values of other configs.
		daemonConfigInitialization,
		// Provide promise that can be used to await initialization of unsafe daemonconfig properties.
		promise.New[*option.DaemonConfig],
		// Provide option.Config via hive so cells can depend on the agent config.
		// It's not safe to access unsafe daemonconfig properties. Either use the promise or depend on legacy.DaemonConfigInitialization.
		func() *option.DaemonConfig { return option.Config },
	),
	cell.Invoke(func(_ legacy.DaemonConfigInitialization) {}), // Force initialization.
)

type daemonConfigParams struct {
	cell.In

	CfgResolver  promise.Resolver[*option.DaemonConfig]
	DaemonConfig *option.DaemonConfig

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group

	K8sClientConfig k8sClient.Config
	KPRConfig       kpr.KPRConfig
	KPRInitializer  kprinitializer.KPRInitializer
	IPSecConfig     datapath.IPsecConfig
	WireguardConfig wgTypes.WireguardConfig
}

type daemonParams struct {
	cell.In

	// Ensures that the legacy daemon config initialization is executed
	legacy.DaemonConfigInitialization
	DaemonConfig *option.DaemonConfig

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle

	Clientset           k8sClient.Clientset
	KVStoreClient       kvstore.Client
	WGAgent             wgTypes.WireguardAgent
	LocalNodeRes        k8s.LocalNodeResource
	LocalCiliumNodeRes  k8s.LocalCiliumNodeResource
	K8sWatcher          *watchers.K8sWatcher
	NodeHandler         datapath.NodeHandler
	EndpointManager     endpointmanager.EndpointManager
	EndpointRestorer    *endpointRestorer
	IdentityAllocator   identitycell.CachingIdentityAllocator
	Policy              policy.PolicyRepository
	MonitorAgent        monitorAgent.Agent
	DB                  *statedb.DB
	Devices             statedb.Table[*datapathTables.Device]
	DirectRoutingDevice datapathTables.DirectRoutingDevice
	IPsecAgent          datapath.IPsecAgent
	SyncHostIPs         *syncHostIPs
	NodeDiscovery       *nodediscovery.NodeDiscovery
	IPAM                *ipam.IPAM
	CRDSyncPromise      promise.Promise[k8sSynced.CRDSync]
	KPRConfig           kpr.KPRConfig
	KPRInitializer      kprinitializer.KPRInitializer
	InfraIPAllocator    infraendpoints.InfraIPAllocator
}

func daemonConfigInitialization(params daemonConfigParams) legacy.DaemonConfigInitialization {
	params.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if err := initAndValidateDaemonConfig(params); err != nil {
				params.CfgResolver.Reject(err)
				return fmt.Errorf("failed to init and validate daemon config: %w", err)
			}

			if !option.Config.DryMode {
				// Store config in file before resolving the DaemonConfig promise.
				if err := option.Config.StoreInFile(params.Logger, option.Config.StateDir); err != nil {
					params.Logger.Error("Unable to store Cilium's configuration", logfields.Error, err)
					params.CfgResolver.Reject(err)
					return err
				}

				if err := option.StoreViperInFile(params.Logger, option.Config.StateDir); err != nil {
					params.Logger.Error("Unable to store Viper's configuration", logfields.Error, err)
					params.CfgResolver.Reject(err)
					return err
				}
			}

			// 'option.Config' is assumed to be stable at this point, except for
			// 'option.Config.Opts' that are explicitly deemed to be runtime-changeable
			params.CfgResolver.Resolve(option.Config)

			return nil
		},
	})

	if !option.Config.DryMode {
		// Register job to validate that daemon config is unchanged
		params.JobGroup.Add(job.Timer(
			"validate-unchanged-daemon-config",
			// Validate that Daemon config has not changed, ignoring 'Opts'
			// that may be modified via config patch events.
			func(ctx context.Context) error { return option.Config.ValidateUnchanged() },
			// avoid synhronized run with other
			// jobs started at same time
			61*time.Second,
		))
	}

	return legacy.DaemonConfigInitialization{}
}

func daemonLegacyInitialization(params daemonParams) legacy.DaemonInitialization {
	// daemonCtx is the daemon-wide context cancelled when stopping.
	daemonCtx, cancelDaemonCtx := context.WithCancel(context.Background())

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			params.Logger.Info("Initializing daemon")
			if err := configureDaemon(daemonCtx, params); err != nil {
				cancelDaemonCtx()
				return fmt.Errorf("daemon configuration failed: %w", err)
			}

			params.Logger.Info("Daemon initialization completed", logfields.BootstrapTime, time.Since(bootstrapTimestamp))

			if err := params.MonitorAgent.SendEvent(monitorAPI.MessageTypeAgent, monitorAPI.StartMessage(time.Now())); err != nil {
				params.Logger.Warn("Failed to send agent start monitor message", logfields.Error, err)
			}

			return nil
		},
		OnStop: func(cell.HookContext) error {
			cancelDaemonCtx()
			unloadDNSPolicies(params)
			pidfile.Clean()
			return nil
		},
	})

	return legacy.DaemonInitialization{}
}

func initClockSourceOption(logger *slog.Logger) {
	option.Config.ClockSource = option.ClockSourceKtime
	hz, err := probes.KernelHZ()
	if err != nil {
		logger.Info(
			fmt.Sprintf("Auto-disabling %q feature since KERNEL_HZ cannot be determined", option.EnableBPFClockProbe),
			logfields.Error, err,
		)
		option.Config.EnableBPFClockProbe = false
	} else {
		option.Config.KernelHz = int(hz)
	}

	if option.Config.EnableBPFClockProbe {
		t, err := probes.Jiffies()
		if err == nil && t > 0 {
			option.Config.ClockSource = option.ClockSourceJiffies
		} else {
			logger.Warn(
				fmt.Sprintf("Auto-disabling %q feature since kernel doesn't expose jiffies", option.EnableBPFClockProbe),
				logfields.Error, err,
			)
			option.Config.EnableBPFClockProbe = false
		}
	}
}
