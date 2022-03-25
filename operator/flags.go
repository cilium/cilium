// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	cobra.OnInitialize(option.InitConfig(rootCmd, "Cilium-Operator", "cilium-operators"))

	flags := rootCmd.Flags()

	flags.Int(operatorOption.IPAMAPIBurst, defaults.IPAMAPIBurst, "Upper burst limit when accessing external APIs")
	option.BindEnv(operatorOption.IPAMAPIBurst)

	flags.Float64(operatorOption.IPAMAPIQPSLimit, defaults.IPAMAPIQPSLimit, "Queries per second limit when accessing external IPAM APIs")
	option.BindEnv(operatorOption.IPAMAPIQPSLimit)

	flags.StringToStringVar(&operatorOption.Config.IPAMSubnetsTags, operatorOption.IPAMSubnetsTags, operatorOption.Config.IPAMSubnetsTags,
		"Subnets tags in the form of k1=v1,k2=v2 (multiple k/v pairs can also be passed by repeating the CLI flag")
	option.BindEnv(operatorOption.IPAMSubnetsTags)

	flags.StringSliceVar(&operatorOption.Config.IPAMSubnetsIDs, operatorOption.IPAMSubnetsIDs, operatorOption.Config.IPAMSubnetsIDs,
		"Subnets IDs (separated by commas)")
	option.BindEnv(operatorOption.IPAMSubnetsIDs)

	flags.StringToStringVar(&operatorOption.Config.IPAMInstanceTags, operatorOption.IPAMInstanceTags, operatorOption.Config.IPAMInstanceTags,
		"EC2 Instance tags in the form of k1=v1,k2=v2 (multiple k/v pairs can also be passed by repeating the CLI flag")
	option.BindEnv(operatorOption.IPAMInstanceTags)

	flags.Int64(operatorOption.ParallelAllocWorkers, defaults.ParallelAllocWorkers, "Maximum number of parallel IPAM workers")
	option.BindEnv(operatorOption.ParallelAllocWorkers)

	// Clustermesh dedicated flags
	flags.Int(option.ClusterIDName, 0, "Unique identifier of the cluster")
	option.BindEnv(option.ClusterIDName)

	flags.String(option.ClusterName, defaults.ClusterName, "Name of the cluster")
	option.BindEnv(option.ClusterName)

	// Operator-specific flags
	flags.String(option.ConfigFile, "", `Configuration file (default "$HOME/ciliumd.yaml")`)
	option.BindEnv(option.ConfigFile)

	flags.String(option.ConfigDir, "", `Configuration directory that contains a file for each option`)
	option.BindEnv(option.ConfigDir)

	flags.Bool(option.DisableCNPStatusUpdates, false, `Do not send CNP NodeStatus updates to the Kubernetes api-server (recommended to run with "cnp-node-status-gc-interval=0" in cilium-operator)`)
	flags.MarkHidden(option.DisableCNPStatusUpdates)
	option.BindEnv(option.DisableCNPStatusUpdates)

	flags.Bool(option.K8sEventHandover, defaults.K8sEventHandover, "Enable k8s event handover to kvstore for improved scalability")
	option.BindEnv(option.K8sEventHandover)

	flags.Duration(operatorOption.CNPNodeStatusGCInterval, 2*time.Minute, "GC interval for nodes which have been removed from the cluster in CiliumNetworkPolicy Status")
	option.BindEnv(operatorOption.CNPNodeStatusGCInterval)

	flags.Duration(operatorOption.CNPStatusUpdateInterval, 1*time.Second, "Interval between CNP status updates sent to the k8s-apiserver per-CNP")
	option.BindEnv(operatorOption.CNPStatusUpdateInterval)

	flags.BoolP(option.DebugArg, "D", false, "Enable debugging mode")
	option.BindEnv(option.DebugArg)

	// We need to obtain from Cilium ConfigMap if these options are enabled
	// or disabled. These options are marked as hidden because having it
	// being printed by operator --help could confuse users.
	flags.Bool(option.DisableCiliumEndpointCRDName, false, "")
	flags.MarkHidden(option.DisableCiliumEndpointCRDName)
	option.BindEnv(option.DisableCiliumEndpointCRDName)

	flags.Bool(option.EnableIPv4EgressGateway, false, "")
	flags.MarkHidden(option.EnableIPv4EgressGateway)
	option.BindEnv(option.EnableIPv4EgressGateway)

	flags.Bool(option.EnableLocalRedirectPolicy, false, "")
	flags.MarkHidden(option.EnableLocalRedirectPolicy)
	option.BindEnv(option.EnableLocalRedirectPolicy)

	flags.Duration(operatorOption.EndpointGCInterval, operatorOption.EndpointGCIntervalDefault, "GC interval for cilium endpoints")
	option.BindEnv(operatorOption.EndpointGCInterval)

	flags.Bool(operatorOption.EnableMetrics, false, "Enable Prometheus metrics")
	option.BindEnv(operatorOption.EnableMetrics)

	// Logging flags
	flags.StringSlice(option.LogDriver, []string{}, "Logging endpoints to use for example syslog")
	option.BindEnv(option.LogDriver)

	flags.Var(option.NewNamedMapOptions(option.LogOpt, &option.Config.LogOpt, nil),
		option.LogOpt, `Log driver options for cilium-operator, `+
			`configmap example for syslog driver: {"syslog.level":"info","syslog.facility":"local4"}`)
	option.BindEnv(option.LogOpt)

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
	option.BindEnv(option.IPAM)

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

	flags.Duration(operatorOption.IdentityHeartbeatTimeout, 2*defaults.KVstoreLeaseTTL, "Timeout after which identity expires on lack of heartbeat")
	option.BindEnv(operatorOption.IdentityHeartbeatTimeout)

	flags.Bool(option.EnableIPv4Name, defaults.EnableIPv4, "Enable IPv4 support")
	option.BindEnv(option.EnableIPv4Name)

	flags.StringSlice(operatorOption.ClusterPoolIPv4CIDR, []string{},
		fmt.Sprintf("IPv4 CIDR Range for Pods in cluster. Requires '%s=%s|%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMClusterPool, ipamOption.IPAMClusterPoolV2,
			option.EnableIPv4Name, "true"))
	option.BindEnv(operatorOption.ClusterPoolIPv4CIDR)

	flags.Int(operatorOption.NodeCIDRMaskSizeIPv4, 24,
		fmt.Sprintf("Mask size for each IPv4 podCIDR per node. Requires '%s=%s|%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMClusterPool, ipamOption.IPAMClusterPoolV2,
			option.EnableIPv4Name, "true"))
	option.BindEnv(operatorOption.NodeCIDRMaskSizeIPv4)

	flags.Bool(option.EnableIPv6Name, defaults.EnableIPv6, "Enable IPv6 support")
	option.BindEnv(option.EnableIPv6Name)

	flags.StringSlice(operatorOption.ClusterPoolIPv6CIDR, []string{},
		fmt.Sprintf("IPv6 CIDR Range for Pods in cluster. Requires '%s=%s|%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMClusterPool, ipamOption.IPAMClusterPoolV2,
			option.EnableIPv6Name, "true"))
	option.BindEnv(operatorOption.ClusterPoolIPv6CIDR)

	flags.Int(operatorOption.NodeCIDRMaskSizeIPv6, 112,
		fmt.Sprintf("Mask size for each IPv6 podCIDR per node. Requires '%s=%s|%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMClusterPool, ipamOption.IPAMClusterPoolV2,
			option.EnableIPv6Name, "true"))
	option.BindEnv(operatorOption.NodeCIDRMaskSizeIPv6)

	flags.String(option.IdentityAllocationMode, option.IdentityAllocationModeKVstore, "Method to use for identity allocation")
	option.BindEnv(option.IdentityAllocationMode)

	flags.Duration(operatorOption.IdentityGCInterval, defaults.KVstoreLeaseTTL, "GC interval for security identities")
	option.BindEnv(operatorOption.IdentityGCInterval)

	flags.Duration(operatorOption.IdentityGCRateInterval, time.Minute,
		"Interval used for rate limiting the GC of security identities")
	option.BindEnv(operatorOption.IdentityGCRateInterval)

	flags.Int(operatorOption.IdentityGCRateLimit, 2500,
		fmt.Sprintf("Maximum number of security identities that will be deleted within the %s", operatorOption.IdentityGCRateInterval))
	option.BindEnv(operatorOption.IdentityGCRateLimit)

	flags.String(option.KVStore, "", "Key-value store type")
	option.BindEnv(option.KVStore)

	flags.Var(option.NewNamedMapOptions(option.KVStoreOpt, &option.Config.KVStoreOpt, nil),
		option.KVStoreOpt, "Key-value store options e.g. etcd.address=127.0.0.1:4001")
	option.BindEnv(option.KVStoreOpt)

	flags.String(option.K8sAPIServer, "", "Kubernetes API server URL")
	option.BindEnv(option.K8sAPIServer)

	flags.Float32(option.K8sClientQPSLimit, defaults.K8sClientQPSLimit, "Queries per second limit for the K8s client")
	flags.Int(option.K8sClientBurst, defaults.K8sClientBurst, "Burst value allowed for the K8s client")

	flags.Bool(option.K8sEnableEndpointSlice, defaults.K8sEnableEndpointSlice, "Enables k8s EndpointSlice feature into Cilium-Operator if the k8s cluster supports it")
	option.BindEnv(option.K8sEnableEndpointSlice)

	flags.Bool(option.K8sEnableAPIDiscovery, defaults.K8sEnableAPIDiscovery, "Enable discovery of Kubernetes API groups and resources with the discovery API")
	option.BindEnv(option.K8sEnableAPIDiscovery)

	flags.String(option.K8sNamespaceName, "", "Name of the Kubernetes namespace in which Cilium Operator is deployed in")
	option.BindEnv(option.K8sNamespaceName)

	flags.String(option.K8sKubeConfigPath, "", "Absolute path of the kubernetes kubeconfig file")
	option.BindEnv(option.K8sKubeConfigPath)

	// To be removed in Cilium 1.12
	flags.Duration(operatorOption.NodesGCInterval, 2*time.Minute, "GC interval for nodes store in the kvstore")
	option.BindEnv(operatorOption.NodesGCInterval)
	flags.MarkDeprecated(operatorOption.NodesGCInterval, "Unused flag, will be removed in future Cilium releases")

	flags.String(operatorOption.OperatorPrometheusServeAddr, operatorOption.PrometheusServeAddr, "Address to serve Prometheus metrics")
	option.BindEnv(operatorOption.OperatorPrometheusServeAddr)

	flags.String(operatorOption.OperatorAPIServeAddr, "localhost:9234", "Address to serve API requests")
	option.BindEnv(operatorOption.OperatorAPIServeAddr)

	flags.Bool(operatorOption.PProf, false, "Enable pprof debugging endpoint")
	option.BindEnv(operatorOption.PProf)

	flags.Int(operatorOption.PProfPort, 6061, "Port that the pprof listens on")
	option.BindEnv(operatorOption.PProfPort)

	flags.Bool(operatorOption.SyncK8sServices, true, "Synchronize Kubernetes services to kvstore")
	option.BindEnv(operatorOption.SyncK8sServices)

	flags.Bool(operatorOption.SyncK8sNodes, true, "Synchronize Kubernetes nodes to kvstore and perform CNP GC")
	option.BindEnv(operatorOption.SyncK8sNodes)

	flags.Int(operatorOption.UnmanagedPodWatcherInterval, 15, "Interval to check for unmanaged kube-dns pods (0 to disable)")
	option.BindEnv(operatorOption.UnmanagedPodWatcherInterval)

	flags.Bool(option.Version, false, "Print version information")
	option.BindEnv(option.Version)

	flags.String(option.CMDRef, "", "Path to cmdref output directory")
	flags.MarkHidden(option.CMDRef)
	option.BindEnv(option.CMDRef)

	flags.Int(option.GopsPort, defaults.GopsPortOperator, "Port for gops server to listen on")
	option.BindEnv(option.GopsPort)

	flags.Duration(option.K8sHeartbeatTimeout, 30*time.Second, "Configures the timeout for api-server heartbeat, set to 0 to disable")
	option.BindEnv(option.K8sHeartbeatTimeout)

	flags.Duration(operatorOption.LeaderElectionLeaseDuration, 15*time.Second,
		"Duration that non-leader operator candidates will wait before forcing to acquire leadership")
	option.BindEnv(operatorOption.LeaderElectionLeaseDuration)

	flags.Duration(operatorOption.LeaderElectionRenewDeadline, 10*time.Second,
		"Duration that current acting master will retry refreshing leadership in before giving up the lock")
	option.BindEnv(operatorOption.LeaderElectionRenewDeadline)

	flags.Duration(operatorOption.LeaderElectionRetryPeriod, 2*time.Second,
		"Duration that LeaderElector clients should wait between retries of the actions")
	option.BindEnv(operatorOption.LeaderElectionRetryPeriod)

	flags.String(option.K8sServiceProxyName, "", "Value of K8s service-proxy-name label for which Cilium handles the services (empty = all services without service.kubernetes.io/service-proxy-name label)")
	option.BindEnv(option.K8sServiceProxyName)

	flags.Bool(option.BGPAnnounceLBIP, false, "Announces service IPs of type LoadBalancer via BGP")
	option.BindEnv(option.BGPAnnounceLBIP)

	flags.String(option.BGPConfigPath, "/var/lib/cilium/bgp/config.yaml", "Path to file containing the BGP configuration")
	option.BindEnv(option.BGPConfigPath)

	flags.Bool(option.SkipCRDCreation, false, "When true, Kubernetes Custom Resource Definitions will not be created")
	option.BindEnv(option.SkipCRDCreation)

	flags.Bool(option.EnableCiliumEndpointSlice, false, "If set to true, the CiliumEndpointSlice feature is enabled. If any CiliumEndpoints resources are created, updated, or deleted in the cluster, all those changes are broadcast as CiliumEndpointSlice updates to all of the Cilium agents.")
	option.BindEnv(option.EnableCiliumEndpointSlice)

	flags.Int(operatorOption.CESMaxCEPsInCES, operatorOption.CESMaxCEPsInCESDefault, "Maximum number of CiliumEndpoints allowed in a CES")
	flags.MarkHidden(operatorOption.CESMaxCEPsInCES)
	option.BindEnv(operatorOption.CESMaxCEPsInCES)

	flags.String(operatorOption.CESSlicingMode, operatorOption.CESSlicingModeDefault, "Slicing mode define how ceps are grouped into a CES")
	flags.MarkHidden(operatorOption.CESSlicingMode)
	option.BindEnv(operatorOption.CESSlicingMode)

	flags.String(operatorOption.CiliumK8sNamespace, "", fmt.Sprintf("Name of the Kubernetes namespace in which Cilium is deployed in. Defaults to the same namespace defined in %s", option.K8sNamespaceName))
	option.BindEnv(operatorOption.CiliumK8sNamespace)

	flags.String(operatorOption.CiliumPodLabels, "k8s-app=cilium", "Cilium Pod's labels. Used to detect if a Cilium pod is running to remove the node taints where its running and set NetworkUnavailable to false")
	option.BindEnv(operatorOption.CiliumPodLabels)

	flags.Bool(operatorOption.RemoveCiliumNodeTaints, true, fmt.Sprintf("Remove node taint %q from Kubernetes nodes once Cilium is up and running", ciliumio.AgentNotReadyNodeTaint))
	option.BindEnv(operatorOption.RemoveCiliumNodeTaints)

	flags.Bool(operatorOption.SetCiliumIsUpCondition, true, "Set CiliumIsUp Node condition to mark a Kubernetes Node that a Cilium pod is up and running in that node")
	option.BindEnv(operatorOption.SetCiliumIsUpCondition)

	viper.BindPFlags(flags)
}
