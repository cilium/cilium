// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/option"
)

func InitGlobalFlags(cmd *cobra.Command, vp *viper.Viper) {
	flags := cmd.Flags()

	flags.Int(operatorOption.IPAMAPIBurst, defaults.IPAMAPIBurst, "Upper burst limit when accessing external APIs")
	option.BindEnv(vp, operatorOption.IPAMAPIBurst)

	flags.Float64(operatorOption.IPAMAPIQPSLimit, defaults.IPAMAPIQPSLimit, "Queries per second limit when accessing external IPAM APIs")
	option.BindEnv(vp, operatorOption.IPAMAPIQPSLimit)

	flags.Var(option.NewNamedMapOptions(operatorOption.IPAMSubnetsTags, &operatorOption.Config.IPAMSubnetsTags, nil),
		operatorOption.IPAMSubnetsTags, "Subnets tags in the form of k1=v1,k2=v2 (multiple k/v pairs can also be passed by repeating the CLI flag")
	option.BindEnv(vp, operatorOption.IPAMSubnetsTags)

	flags.StringSliceVar(&operatorOption.Config.IPAMSubnetsIDs, operatorOption.IPAMSubnetsIDs, operatorOption.Config.IPAMSubnetsIDs,
		"Subnets IDs (separated by commas)")
	option.BindEnv(vp, operatorOption.IPAMSubnetsIDs)

	flags.Var(option.NewNamedMapOptions(operatorOption.IPAMInstanceTags, &operatorOption.Config.IPAMInstanceTags, nil), operatorOption.IPAMInstanceTags,
		"EC2 Instance tags in the form of k1=v1,k2=v2 (multiple k/v pairs can also be passed by repeating the CLI flag")
	option.BindEnv(vp, operatorOption.IPAMInstanceTags)

	flags.Var(option.NewNamedMapOptions(operatorOption.IPAMAutoCreateCiliumPodIPPools, &operatorOption.Config.IPAMAutoCreateCiliumPodIPPools, nil),
		operatorOption.IPAMAutoCreateCiliumPodIPPools,
		"Automatically create CiliumPodIPPool resources on startup. "+
			"Specify pools in the form of <pool>=ipv4-cidrs:<cidr>,[<cidr>...];ipv4-mask-size:<size> (multiple pools can also be passed by repeating the CLI flag)")
	option.BindEnv(vp, operatorOption.IPAMAutoCreateCiliumPodIPPools)

	flags.Int64(operatorOption.ParallelAllocWorkers, defaults.ParallelAllocWorkers, "Maximum number of parallel IPAM workers")
	option.BindEnv(vp, operatorOption.ParallelAllocWorkers)

	// Operator-specific flags
	flags.String(option.ConfigFile, "", `Configuration file (default "$HOME/ciliumd.yaml")`)
	option.BindEnv(vp, option.ConfigFile)

	flags.String(option.ConfigDir, "", `Configuration directory that contains a file for each option`)
	option.BindEnv(vp, option.ConfigDir)

	flags.BoolP(option.DebugArg, "D", false, "Enable debugging mode")
	option.BindEnv(vp, option.DebugArg)

	// We need to obtain from Cilium ConfigMap if these options are enabled
	// or disabled. These options are marked as hidden because having it
	// being printed by operator --help could confuse users.
	flags.Bool(option.DisableCiliumEndpointCRDName, false, "")
	flags.MarkHidden(option.DisableCiliumEndpointCRDName)
	option.BindEnv(vp, option.DisableCiliumEndpointCRDName)

	flags.Bool(option.EnableIPv4EgressGateway, false, "")
	flags.MarkHidden(option.EnableIPv4EgressGateway)
	option.BindEnv(vp, option.EnableIPv4EgressGateway)

	flags.Bool(option.EnableLocalRedirectPolicy, false, "")
	flags.MarkHidden(option.EnableLocalRedirectPolicy)
	option.BindEnv(vp, option.EnableLocalRedirectPolicy)

	flags.Bool(option.EnableSRv6, false, "")
	flags.MarkHidden(option.EnableSRv6)
	option.BindEnv(vp, option.EnableSRv6)

	flags.Duration(operatorOption.EndpointGCInterval, operatorOption.EndpointGCIntervalDefault, "GC interval for cilium endpoints")
	option.BindEnv(vp, operatorOption.EndpointGCInterval)

	flags.Bool(operatorOption.EnableMetrics, false, "Enable Prometheus metrics")
	option.BindEnv(vp, operatorOption.EnableMetrics)

	// Logging flags
	flags.StringSlice(option.LogDriver, []string{}, "Logging endpoints to use for example syslog")
	option.BindEnv(vp, option.LogDriver)

	flags.Var(option.NewNamedMapOptions(option.LogOpt, &option.Config.LogOpt, nil),
		option.LogOpt, `Log driver options for cilium-operator, `+
			`configmap example for syslog driver: {"syslog.level":"info","syslog.facility":"local4"}`)
	option.BindEnv(vp, option.LogOpt)

	var defaultIPAM string
	switch binaryName {
	case "cilium-operator":
		defaultIPAM = ipamOption.IPAMClusterPool
	case "cilium-operator-aws":
		defaultIPAM = ipamOption.IPAMENI
	case "cilium-operator-azure":
		defaultIPAM = ipamOption.IPAMAzure
	case "cilium-operator-alibabacloud":
		defaultIPAM = ipamOption.IPAMAlibabaCloud
	case "cilium-operator-generic":
		defaultIPAM = ipamOption.IPAMClusterPool
	}

	flags.String(option.IPAM, defaultIPAM, "Backend to use for IPAM")
	option.BindEnv(vp, option.IPAM)

	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		ipamFlag := cmd.Flag(option.IPAM)
		if !ipamFlag.Changed {
			return nil
		}
		ipamFlagValue := ipamFlag.Value.String()

		recommendInstead := func() string {
			switch ipamFlagValue {
			case ipamOption.IPAMENI:
				return "cilium-operator-aws"
			case ipamOption.IPAMAzure:
				return "cilium-operator-azure"
			case ipamOption.IPAMAlibabaCloud:
				return "cilium-operator-alibabacloud"
			case ipamOption.IPAMKubernetes, ipamOption.IPAMClusterPool, ipamOption.IPAMCRD:
				return "cilium-operator-generic"
			default:
				return ""
			}
		}

		unsupporterErr := func() error {
			errMsg := fmt.Sprintf("%s doesn't support --%s=%s", binaryName, option.IPAM, ipamFlagValue)
			if recommendation := recommendInstead(); recommendation != "" {
				return fmt.Errorf("%s (use %s)", errMsg, recommendation)
			}
			return fmt.Errorf(errMsg)
		}

		switch binaryName {
		case "cilium-operator":
			if recommendation := recommendInstead(); recommendation != "" {
				log.Warnf("cilium-operator will be deprecated in the future, for --%s=%s use %s as it has lower memory footprint", option.IPAM, ipamFlagValue, recommendation)
			}
		case "cilium-operator-aws":
			if ipamFlagValue != ipamOption.IPAMENI {
				return unsupporterErr()
			}
		case "cilium-operator-azure":
			if ipamFlagValue != ipamOption.IPAMAzure {
				return unsupporterErr()
			}
		case "cilium-operator-alibabacloud":
			if ipamFlagValue != ipamOption.IPAMAlibabaCloud {
				return unsupporterErr()
			}
		case "cilium-operator-generic":
			switch ipamFlagValue {
			case ipamOption.IPAMENI, ipamOption.IPAMAzure, ipamOption.IPAMAlibabaCloud:
				return unsupporterErr()
			}
		}

		return nil
	}

	flags.Bool(option.EnableIPv4Name, defaults.EnableIPv4, "Enable IPv4 support")
	option.BindEnv(vp, option.EnableIPv4Name)

	flags.StringSlice(operatorOption.ClusterPoolIPv4CIDR, []string{},
		fmt.Sprintf("IPv4 CIDR Range for Pods in cluster. Requires '%s=%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMClusterPool,
			option.EnableIPv4Name, "true"))
	option.BindEnv(vp, operatorOption.ClusterPoolIPv4CIDR)

	flags.Int(operatorOption.NodeCIDRMaskSizeIPv4, 24,
		fmt.Sprintf("Mask size for each IPv4 podCIDR per node. Requires '%s=%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMClusterPool,
			option.EnableIPv4Name, "true"))
	option.BindEnv(vp, operatorOption.NodeCIDRMaskSizeIPv4)

	flags.Bool(option.EnableIPv6Name, defaults.EnableIPv6, "Enable IPv6 support")
	option.BindEnv(vp, option.EnableIPv6Name)

	flags.StringSlice(operatorOption.ClusterPoolIPv6CIDR, []string{},
		fmt.Sprintf("IPv6 CIDR Range for Pods in cluster. Requires '%s=%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMClusterPool,
			option.EnableIPv6Name, "true"))
	option.BindEnv(vp, operatorOption.ClusterPoolIPv6CIDR)

	flags.Int(operatorOption.NodeCIDRMaskSizeIPv6, 112,
		fmt.Sprintf("Mask size for each IPv6 podCIDR per node. Requires '%s=%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMClusterPool,
			option.EnableIPv6Name, "true"))
	option.BindEnv(vp, operatorOption.NodeCIDRMaskSizeIPv6)

	flags.String(option.IdentityAllocationMode, option.IdentityAllocationModeKVstore, "Method to use for identity allocation")
	option.BindEnv(vp, option.IdentityAllocationMode)

	flags.String(option.KVStore, "", "Key-value store type")
	option.BindEnv(vp, option.KVStore)

	flags.Var(option.NewNamedMapOptions(option.KVStoreOpt, &option.Config.KVStoreOpt, nil),
		option.KVStoreOpt, "Key-value store options e.g. etcd.address=127.0.0.1:4001")
	option.BindEnv(vp, option.KVStoreOpt)

	flags.String(option.K8sNamespaceName, "", "Name of the Kubernetes namespace in which Cilium Operator is deployed in")
	option.BindEnv(vp, option.K8sNamespaceName)

	flags.Duration(operatorOption.NodesGCInterval, 5*time.Minute, "GC interval for CiliumNodes")
	option.BindEnv(vp, operatorOption.NodesGCInterval)

	flags.Bool(operatorOption.SyncK8sServices, true, "Synchronize Kubernetes services to kvstore")
	option.BindEnv(vp, operatorOption.SyncK8sServices)

	flags.Bool(operatorOption.SyncK8sNodes, true, "Synchronize Kubernetes nodes to kvstore and perform CNP GC")
	option.BindEnv(vp, operatorOption.SyncK8sNodes)

	flags.Int(operatorOption.UnmanagedPodWatcherInterval, 15, "Interval to check for unmanaged kube-dns pods (0 to disable)")
	option.BindEnv(vp, operatorOption.UnmanagedPodWatcherInterval)

	flags.Bool(option.Version, false, "Print version information")
	option.BindEnv(vp, option.Version)

	flags.String(option.CMDRef, "", "Path to cmdref output directory")
	flags.MarkHidden(option.CMDRef)
	option.BindEnv(vp, option.CMDRef)

	flags.Duration(operatorOption.LeaderElectionLeaseDuration, 15*time.Second,
		"Duration that non-leader operator candidates will wait before forcing to acquire leadership")
	option.BindEnv(vp, operatorOption.LeaderElectionLeaseDuration)

	flags.Duration(operatorOption.LeaderElectionRenewDeadline, 10*time.Second,
		"Duration that current acting master will retry refreshing leadership in before giving up the lock")
	option.BindEnv(vp, operatorOption.LeaderElectionRenewDeadline)

	flags.Duration(operatorOption.LeaderElectionRetryPeriod, 2*time.Second,
		"Duration that LeaderElector clients should wait between retries of the actions")
	option.BindEnv(vp, operatorOption.LeaderElectionRetryPeriod)

	flags.Bool(option.BGPAnnounceLBIP, false, "Announces service IPs of type LoadBalancer via BGP")
	option.BindEnv(vp, option.BGPAnnounceLBIP)

	flags.String(option.BGPConfigPath, "/var/lib/cilium/bgp/config.yaml", "Path to file containing the BGP configuration")
	option.BindEnv(vp, option.BGPConfigPath)

	flags.Bool(option.EnableCiliumEndpointSlice, false, "If set to true, the CiliumEndpointSlice feature is enabled. If any CiliumEndpoints resources are created, updated, or deleted in the cluster, all those changes are broadcast as CiliumEndpointSlice updates to all of the Cilium agents.")
	option.BindEnv(vp, option.EnableCiliumEndpointSlice)

	flags.String(operatorOption.CiliumK8sNamespace, "", fmt.Sprintf("Name of the Kubernetes namespace in which Cilium is deployed in. Defaults to the same namespace defined in %s", option.K8sNamespaceName))
	option.BindEnv(vp, operatorOption.CiliumK8sNamespace)

	flags.String(operatorOption.CiliumPodLabels, "k8s-app=cilium", "Cilium Pod's labels. Used to detect if a Cilium pod is running to remove the node taints where its running and set NetworkUnavailable to false")
	option.BindEnv(vp, operatorOption.CiliumPodLabels)

	flags.Bool(operatorOption.RemoveCiliumNodeTaints, true, fmt.Sprintf("Remove node taint %q from Kubernetes nodes once Cilium is up and running", option.Config.AgentNotReadyNodeTaintValue()))
	option.BindEnv(vp, operatorOption.RemoveCiliumNodeTaints)

	flags.Bool(operatorOption.SetCiliumNodeTaints, false, fmt.Sprintf("Set node taint %q from Kubernetes nodes if Cilium is scheduled but not up and running", option.Config.AgentNotReadyNodeTaintValue()))
	option.BindEnv(vp, operatorOption.SetCiliumNodeTaints)

	flags.Bool(operatorOption.SetCiliumIsUpCondition, true, "Set CiliumIsUp Node condition to mark a Kubernetes Node that a Cilium pod is up and running in that node")
	option.BindEnv(vp, operatorOption.SetCiliumIsUpCondition)

	flags.String(operatorOption.PodRestartSelector, "k8s-app=kube-dns", "cilium-operator will delete/restart any pods with these labels if the pod is not managed by Cilium. If this option is empty, then all pods may be restarted")
	option.BindEnv(vp, operatorOption.PodRestartSelector)

	flags.Duration(option.KVstoreLeaseTTL, defaults.KVstoreLeaseTTL, "Time-to-live for the KVstore lease.")
	flags.MarkHidden(option.KVstoreLeaseTTL)
	option.BindEnv(vp, option.KVstoreLeaseTTL)

	vp.BindPFlags(flags)
}

const (
	// pprofOperator enables pprof debugging endpoint for the operator
	pprofOperator = "operator-pprof"

	// pprofAddress is the port that the pprof listens on
	pprofAddress = "operator-pprof-address"

	// pprofPort is the port that the pprof listens on
	pprofPort = "operator-pprof-port"

	k8sClientQps = "operator-k8s-client-qps"

	k8sClientBurst = "operator-k8s-client-burst"
)

// operatorPprofConfig holds the configuration for the operator pprof cell.
// Differently from the agent and the clustermesh-apiserver, the operator prefixes
// the pprof related flags with the string "operator-".
// To reuse the same cell, we need a different config type to map the same fields
// to the operator-specific pprof flag names.
type operatorPprofConfig struct {
	OperatorPprof        bool
	OperatorPprofAddress string
	OperatorPprofPort    uint16
}

func (def operatorPprofConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(pprofOperator, def.OperatorPprof, "Enable serving pprof debugging API")
	flags.String(pprofAddress, def.OperatorPprofAddress, "Address that pprof listens on")
	flags.Uint16(pprofPort, def.OperatorPprofPort, "Port that pprof listens on")
}

type operatorClientParams struct {
	OperatorK8sClientQPS   float32
	OperatorK8sClientBurst int
}

func (def operatorClientParams) Flags(flags *pflag.FlagSet) {
	flags.Float32(k8sClientQps, def.OperatorK8sClientQPS, "Queries per second limit for the K8s client")
	flags.Int(k8sClientBurst, def.OperatorK8sClientBurst, "Burst value allowed for the K8s client")
}
