// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	cobra.OnInitialize(option.InitConfig(rootCmd, "Cilium-Operator", "cilium-operators", Vp))

	flags := rootCmd.Flags()

	flags.Int(operatorOption.IPAMAPIBurst, defaults.IPAMAPIBurst, "Upper burst limit when accessing external APIs")
	option.BindEnv(Vp, operatorOption.IPAMAPIBurst)

	flags.Float64(operatorOption.IPAMAPIQPSLimit, defaults.IPAMAPIQPSLimit, "Queries per second limit when accessing external IPAM APIs")
	option.BindEnv(Vp, operatorOption.IPAMAPIQPSLimit)

	flags.Var(option.NewNamedMapOptions(operatorOption.IPAMSubnetsTags, &operatorOption.Config.IPAMSubnetsTags, nil),
		operatorOption.IPAMSubnetsTags, "Subnets tags in the form of k1=v1,k2=v2 (multiple k/v pairs can also be passed by repeating the CLI flag")
	option.BindEnv(Vp, operatorOption.IPAMSubnetsTags)

	flags.StringSliceVar(&operatorOption.Config.IPAMSubnetsIDs, operatorOption.IPAMSubnetsIDs, operatorOption.Config.IPAMSubnetsIDs,
		"Subnets IDs (separated by commas)")
	option.BindEnv(Vp, operatorOption.IPAMSubnetsIDs)

	flags.Var(option.NewNamedMapOptions(operatorOption.IPAMInstanceTags, &operatorOption.Config.IPAMInstanceTags, nil), operatorOption.IPAMInstanceTags,
		"EC2 Instance tags in the form of k1=v1,k2=v2 (multiple k/v pairs can also be passed by repeating the CLI flag")
	option.BindEnv(Vp, operatorOption.IPAMInstanceTags)

	flags.Var(option.NewNamedMapOptions(operatorOption.IPAMMultiPoolMap, &operatorOption.Config.IPAMMultiPoolMap, nil), operatorOption.IPAMMultiPoolMap,
		"IP pool definitions in the form <pool>=ipv4-cidrs:<cidr>,[<cidr>...];ipv4-mask-size:<size> (multiple pools can also be passed by repeating the CLI flag)")
	flags.MarkHidden(operatorOption.IPAMMultiPoolMap)
	option.BindEnv(Vp, operatorOption.IPAMMultiPoolMap)

	flags.Int64(operatorOption.ParallelAllocWorkers, defaults.ParallelAllocWorkers, "Maximum number of parallel IPAM workers")
	option.BindEnv(Vp, operatorOption.ParallelAllocWorkers)

	// Clustermesh dedicated flags
	flags.Uint32(option.ClusterIDName, 0, "Unique identifier of the cluster")
	option.BindEnv(Vp, option.ClusterIDName)

	flags.String(option.ClusterName, defaults.ClusterName, "Name of the cluster")
	option.BindEnv(Vp, option.ClusterName)

	// Operator-specific flags
	flags.String(option.ConfigFile, "", `Configuration file (default "$HOME/ciliumd.yaml")`)
	option.BindEnv(Vp, option.ConfigFile)

	flags.String(option.ConfigDir, "", `Configuration directory that contains a file for each option`)
	option.BindEnv(Vp, option.ConfigDir)

	flags.Bool(option.DisableCNPStatusUpdates, false, `Do not send CNP NodeStatus updates to the Kubernetes api-server (recommended to run with "cnp-node-status-gc-interval=0" in cilium-operator)`)
	flags.MarkHidden(option.DisableCNPStatusUpdates)
	option.BindEnv(Vp, option.DisableCNPStatusUpdates)

	flags.Bool(option.K8sEventHandover, defaults.K8sEventHandover, "Enable k8s event handover to kvstore for improved scalability")
	option.BindEnv(Vp, option.K8sEventHandover)

	flags.Duration(operatorOption.CNPNodeStatusGCInterval, 2*time.Minute, "GC interval for nodes which have been removed from the cluster in CiliumNetworkPolicy Status")
	option.BindEnv(Vp, operatorOption.CNPNodeStatusGCInterval)

	flags.Bool(operatorOption.SkipCNPStatusStartupClean, false, `If set to true, the operator will not clean up CNP node status updates at startup`)
	option.BindEnv(Vp, operatorOption.SkipCNPStatusStartupClean)

	flags.Float64(operatorOption.CNPStatusCleanupQPS, operatorOption.CNPStatusCleanupQPSDefault,
		"Rate used for limiting the clean up of the status nodes updates in CNP, expressed as qps")
	option.BindEnv(Vp, operatorOption.CNPStatusCleanupQPS)

	flags.Int(operatorOption.CNPStatusCleanupBurst, operatorOption.CNPStatusCleanupBurstDefault,
		"Maximum burst of requests to clean up status nodes updates in CNPs")
	option.BindEnv(Vp, operatorOption.CNPStatusCleanupBurst)

	flags.Duration(operatorOption.CNPStatusUpdateInterval, 1*time.Second, "Interval between CNP status updates sent to the k8s-apiserver per-CNP")
	option.BindEnv(Vp, operatorOption.CNPStatusUpdateInterval)

	flags.BoolP(option.DebugArg, "D", false, "Enable debugging mode")
	option.BindEnv(Vp, option.DebugArg)

	// We need to obtain from Cilium ConfigMap if these options are enabled
	// or disabled. These options are marked as hidden because having it
	// being printed by operator --help could confuse users.
	flags.Bool(option.DisableCiliumEndpointCRDName, false, "")
	flags.MarkHidden(option.DisableCiliumEndpointCRDName)
	option.BindEnv(Vp, option.DisableCiliumEndpointCRDName)

	flags.Bool(option.EnableIPv4EgressGateway, false, "")
	flags.MarkHidden(option.EnableIPv4EgressGateway)
	option.BindEnv(Vp, option.EnableIPv4EgressGateway)

	flags.Bool(option.EnableLocalRedirectPolicy, false, "")
	flags.MarkHidden(option.EnableLocalRedirectPolicy)
	option.BindEnv(Vp, option.EnableLocalRedirectPolicy)

	flags.Bool(option.EnableSRv6, false, "")
	flags.MarkHidden(option.EnableSRv6)
	option.BindEnv(Vp, option.EnableSRv6)

	flags.Duration(operatorOption.EndpointGCInterval, operatorOption.EndpointGCIntervalDefault, "GC interval for cilium endpoints")
	option.BindEnv(Vp, operatorOption.EndpointGCInterval)

	flags.Bool(operatorOption.EnableMetrics, false, "Enable Prometheus metrics")
	option.BindEnv(Vp, operatorOption.EnableMetrics)

	// Logging flags
	flags.StringSlice(option.LogDriver, []string{}, "Logging endpoints to use for example syslog")
	option.BindEnv(Vp, option.LogDriver)

	flags.Var(option.NewNamedMapOptions(option.LogOpt, &option.Config.LogOpt, nil),
		option.LogOpt, `Log driver options for cilium-operator, `+
			`configmap example for syslog driver: {"syslog.level":"info","syslog.facility":"local4"}`)
	option.BindEnv(Vp, option.LogOpt)

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
	option.BindEnv(Vp, option.IPAM)

	rootCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
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
			case ipamOption.IPAMKubernetes, ipamOption.IPAMClusterPool, ipamOption.IPAMClusterPoolV2, ipamOption.IPAMCRD:
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
	option.BindEnv(Vp, option.EnableIPv4Name)

	flags.StringSlice(operatorOption.ClusterPoolIPv4CIDR, []string{},
		fmt.Sprintf("IPv4 CIDR Range for Pods in cluster. Requires '%s=%s|%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMClusterPool, ipamOption.IPAMClusterPoolV2,
			option.EnableIPv4Name, "true"))
	option.BindEnv(Vp, operatorOption.ClusterPoolIPv4CIDR)

	flags.Int(operatorOption.NodeCIDRMaskSizeIPv4, 24,
		fmt.Sprintf("Mask size for each IPv4 podCIDR per node. Requires '%s=%s|%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMClusterPool, ipamOption.IPAMClusterPoolV2,
			option.EnableIPv4Name, "true"))
	option.BindEnv(Vp, operatorOption.NodeCIDRMaskSizeIPv4)

	flags.Bool(option.EnableIPv6Name, defaults.EnableIPv6, "Enable IPv6 support")
	option.BindEnv(Vp, option.EnableIPv6Name)

	flags.StringSlice(operatorOption.ClusterPoolIPv6CIDR, []string{},
		fmt.Sprintf("IPv6 CIDR Range for Pods in cluster. Requires '%s=%s|%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMClusterPool, ipamOption.IPAMClusterPoolV2,
			option.EnableIPv6Name, "true"))
	option.BindEnv(Vp, operatorOption.ClusterPoolIPv6CIDR)

	flags.Int(operatorOption.NodeCIDRMaskSizeIPv6, 112,
		fmt.Sprintf("Mask size for each IPv6 podCIDR per node. Requires '%s=%s|%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMClusterPool, ipamOption.IPAMClusterPoolV2,
			option.EnableIPv6Name, "true"))
	option.BindEnv(Vp, operatorOption.NodeCIDRMaskSizeIPv6)

	flags.String(option.IdentityAllocationMode, option.IdentityAllocationModeKVstore, "Method to use for identity allocation")
	option.BindEnv(Vp, option.IdentityAllocationMode)

	flags.String(option.KVStore, "", "Key-value store type")
	option.BindEnv(Vp, option.KVStore)

	flags.Var(option.NewNamedMapOptions(option.KVStoreOpt, &option.Config.KVStoreOpt, nil),
		option.KVStoreOpt, "Key-value store options e.g. etcd.address=127.0.0.1:4001")
	option.BindEnv(Vp, option.KVStoreOpt)

	flags.Bool(option.K8sEnableEndpointSlice, defaults.K8sEnableEndpointSlice, "Enables k8s EndpointSlice feature into Cilium-Operator if the k8s cluster supports it")
	option.BindEnv(Vp, option.K8sEnableEndpointSlice)

	flags.String(option.K8sNamespaceName, "", "Name of the Kubernetes namespace in which Cilium Operator is deployed in")
	option.BindEnv(Vp, option.K8sNamespaceName)

	flags.Duration(operatorOption.NodesGCInterval, 5*time.Minute, "GC interval for CiliumNodes")
	option.BindEnv(Vp, operatorOption.NodesGCInterval)

	flags.String(operatorOption.OperatorPrometheusServeAddr, operatorOption.PrometheusServeAddr, "Address to serve Prometheus metrics")
	option.BindEnv(Vp, operatorOption.OperatorPrometheusServeAddr)

	flags.Bool(operatorOption.SyncK8sServices, true, "Synchronize Kubernetes services to kvstore")
	option.BindEnv(Vp, operatorOption.SyncK8sServices)

	flags.Bool(operatorOption.SyncK8sNodes, true, "Synchronize Kubernetes nodes to kvstore and perform CNP GC")
	option.BindEnv(Vp, operatorOption.SyncK8sNodes)

	flags.Int(operatorOption.UnmanagedPodWatcherInterval, 15, "Interval to check for unmanaged kube-dns pods (0 to disable)")
	option.BindEnv(Vp, operatorOption.UnmanagedPodWatcherInterval)

	flags.Bool(option.Version, false, "Print version information")
	option.BindEnv(Vp, option.Version)

	flags.String(option.CMDRef, "", "Path to cmdref output directory")
	flags.MarkHidden(option.CMDRef)
	option.BindEnv(Vp, option.CMDRef)

	flags.Duration(operatorOption.LeaderElectionLeaseDuration, 15*time.Second,
		"Duration that non-leader operator candidates will wait before forcing to acquire leadership")
	option.BindEnv(Vp, operatorOption.LeaderElectionLeaseDuration)

	flags.Duration(operatorOption.LeaderElectionRenewDeadline, 10*time.Second,
		"Duration that current acting master will retry refreshing leadership in before giving up the lock")
	option.BindEnv(Vp, operatorOption.LeaderElectionRenewDeadline)

	flags.Duration(operatorOption.LeaderElectionRetryPeriod, 2*time.Second,
		"Duration that LeaderElector clients should wait between retries of the actions")
	option.BindEnv(Vp, operatorOption.LeaderElectionRetryPeriod)

	flags.String(option.K8sServiceProxyName, "", "Value of K8s service-proxy-name label for which Cilium handles the services (empty = all services without service.kubernetes.io/service-proxy-name label)")
	option.BindEnv(Vp, option.K8sServiceProxyName)

	flags.Bool(option.BGPAnnounceLBIP, false, "Announces service IPs of type LoadBalancer via BGP")
	option.BindEnv(Vp, option.BGPAnnounceLBIP)

	flags.String(option.BGPConfigPath, "/var/lib/cilium/bgp/config.yaml", "Path to file containing the BGP configuration")
	option.BindEnv(Vp, option.BGPConfigPath)

	flags.Bool(option.EnableCiliumEndpointSlice, false, "If set to true, the CiliumEndpointSlice feature is enabled. If any CiliumEndpoints resources are created, updated, or deleted in the cluster, all those changes are broadcast as CiliumEndpointSlice updates to all of the Cilium agents.")
	option.BindEnv(Vp, option.EnableCiliumEndpointSlice)

	flags.Int(operatorOption.CESMaxCEPsInCES, operatorOption.CESMaxCEPsInCESDefault, "Maximum number of CiliumEndpoints allowed in a CES")
	flags.MarkHidden(operatorOption.CESMaxCEPsInCES)
	option.BindEnv(Vp, operatorOption.CESMaxCEPsInCES)

	flags.String(operatorOption.CESSlicingMode, operatorOption.CESSlicingModeDefault, "Slicing mode define how ceps are grouped into a CES")
	flags.MarkHidden(operatorOption.CESSlicingMode)
	option.BindEnv(Vp, operatorOption.CESSlicingMode)

	flags.String(operatorOption.CiliumK8sNamespace, "", fmt.Sprintf("Name of the Kubernetes namespace in which Cilium is deployed in. Defaults to the same namespace defined in %s", option.K8sNamespaceName))
	option.BindEnv(Vp, operatorOption.CiliumK8sNamespace)

	flags.String(operatorOption.CiliumPodLabels, "k8s-app=cilium", "Cilium Pod's labels. Used to detect if a Cilium pod is running to remove the node taints where its running and set NetworkUnavailable to false")
	option.BindEnv(Vp, operatorOption.CiliumPodLabels)

	flags.Bool(operatorOption.RemoveCiliumNodeTaints, true, fmt.Sprintf("Remove node taint %q from Kubernetes nodes once Cilium is up and running", option.Config.AgentNotReadyNodeTaintValue()))
	option.BindEnv(Vp, operatorOption.RemoveCiliumNodeTaints)

	flags.Bool(operatorOption.SetCiliumNodeTaints, false, fmt.Sprintf("Set node taint %q from Kubernetes nodes if Cilium is scheduled but not up and running", option.Config.AgentNotReadyNodeTaintValue()))
	option.BindEnv(Vp, operatorOption.SetCiliumNodeTaints)

	flags.Bool(operatorOption.SetCiliumIsUpCondition, true, "Set CiliumIsUp Node condition to mark a Kubernetes Node that a Cilium pod is up and running in that node")
	option.BindEnv(Vp, operatorOption.SetCiliumIsUpCondition)

	flags.StringSlice(operatorOption.IngressLBAnnotationPrefixes, operatorOption.IngressLBAnnotationsDefault, "Annotation prefixes for propagating from Ingress to the Load Balancer service")
	option.BindEnv(Vp, operatorOption.IngressLBAnnotationPrefixes)

	flags.String(operatorOption.PodRestartSelector, "k8s-app=kube-dns", "cilium-operator will delete/restart any pods with these labels if the pod is not managed by Cilium. If this option is empty, then all pods may be restarted")
	option.BindEnv(Vp, operatorOption.PodRestartSelector)

	flags.Duration(option.KVstoreLeaseTTL, defaults.KVstoreLeaseTTL, "Time-to-live for the KVstore lease.")
	flags.MarkHidden(option.KVstoreLeaseTTL)
	option.BindEnv(Vp, option.KVstoreLeaseTTL)

	Vp.BindPFlags(flags)
}

const (
	// pprofOperator enables pprof debugging endpoint for the operator
	pprofOperator = "operator-pprof"

	// pprofAddress is the port that the pprof listens on
	pprofAddress = "operator-pprof-address"

	// pprofPort is the port that the pprof listens on
	pprofPort = "operator-pprof-port"
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
