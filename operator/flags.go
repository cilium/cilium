// Copyright 2020 Authors of Cilium
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
	"time"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/option"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	cobra.OnInitialize(option.InitConfig("Cilium-Operator", "cilium-operators"))

	flags := rootCmd.Flags()

	flags.Int(operatorOption.AWSClientBurstDeprecated, defaults.IPAMAPIBurst, "")
	flags.MarkDeprecated(operatorOption.AWSClientBurstDeprecated, fmt.Sprintf("please use --%s", operatorOption.IPAMAPIBurst))

	flags.Int(operatorOption.IPAMAPIBurst, defaults.IPAMAPIBurst, "Upper burst limit when accessing external APIs")
	option.BindEnv(operatorOption.IPAMAPIBurst)

	flags.Float64(operatorOption.AWSClientQPSLimitDeprecated, defaults.IPAMAPIQPSLimit, "")
	flags.MarkDeprecated(operatorOption.AWSClientQPSLimitDeprecated, fmt.Sprintf("please use --%s", operatorOption.IPAMAPIQPSLimit))

	flags.Float64(operatorOption.IPAMAPIQPSLimit, defaults.IPAMAPIQPSLimit, "Queries per second limit when accessing external IPAM APIs")
	option.BindEnv(operatorOption.IPAMAPIQPSLimit)

	flags.StringToStringVar(&operatorOption.Config.IPAMSubnetsTags, operatorOption.IPAMSubnetsTags, operatorOption.Config.IPAMSubnetsTags,
		"Subnets tags in the form of k1=v1,k2=v2 (multiple k/v pairs can also be passed by repeating the CLI flag")
	option.BindEnv(operatorOption.IPAMSubnetsTags)

	flags.StringSliceVar(&operatorOption.Config.IPAMSubnetsIDs, operatorOption.IPAMSubnetsIDs, operatorOption.Config.IPAMSubnetsIDs,
		"Subnets IDs (separated by commas)")
	option.BindEnv(operatorOption.IPAMSubnetsIDs)

	flags.Int64(operatorOption.ENIParallelWorkersDeprecated, defaults.ParallelAllocWorkers, "")
	flags.MarkDeprecated(operatorOption.ENIParallelWorkersDeprecated, fmt.Sprintf("please use --%s", operatorOption.ParallelAllocWorkers))
	option.BindEnv(operatorOption.ENIParallelWorkersDeprecated)

	flags.Int64(operatorOption.ParallelAllocWorkers, defaults.ParallelAllocWorkers, "Maximum number of parallel IPAM workers")
	option.BindEnv(operatorOption.ParallelAllocWorkers)

	flags.Bool(operatorOption.UpdateEC2AdapterLimitViaAPI, false, "Use the EC2 API to update the instance type to adapter limits")
	option.BindEnv(operatorOption.UpdateEC2AdapterLimitViaAPI)

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

	// Deprecated, remove in 1.9
	flags.Bool(operatorOption.EnableCCNPNodeStatusGC, true, "Enable CiliumClusterwideNetworkPolicy Status garbage collection for nodes which have been removed from the cluster")
	option.BindEnv(operatorOption.EnableCCNPNodeStatusGC)
	flags.MarkDeprecated(operatorOption.EnableCCNPNodeStatusGC, fmt.Sprintf("Please use %s=0 to disable CCNP Status GC", operatorOption.CNPNodeStatusGCInterval))

	// Deprecated, remove in 1.9
	flags.Bool(operatorOption.EnableCNPNodeStatusGC, true, "Enable CiliumNetworkPolicy Status garbage collection for nodes which have been removed from the cluster")
	option.BindEnv(operatorOption.EnableCNPNodeStatusGC)
	flags.MarkDeprecated(operatorOption.EnableCNPNodeStatusGC, fmt.Sprintf("Please use %s=0 to disable CNP Status GC", operatorOption.CNPNodeStatusGCInterval))

	flags.Duration(operatorOption.CNPNodeStatusGCInterval, 2*time.Minute, "GC interval for nodes which have been removed from the cluster in CiliumNetworkPolicy Status")
	option.BindEnv(operatorOption.CNPNodeStatusGCInterval)

	flags.Duration(operatorOption.CNPStatusUpdateInterval, 1*time.Second, "Interval between CNP status updates sent to the k8s-apiserver per-CNP")
	option.BindEnv(operatorOption.CNPStatusUpdateInterval)

	flags.BoolP(option.DebugArg, "D", false, "Enable debugging mode")
	option.BindEnv(option.DebugArg)

	// We need to obtain from Cilium ConfigMap if the CiliumEndpointCRD option
	// is enabled or disabled. This option is marked as hidden because the
	// Cilium Endpoint CRD controller is not in this program and by having it
	// being printed by operator --help could confuse users.
	flags.Bool(option.DisableCiliumEndpointCRDName, false, "")
	flags.MarkHidden(option.DisableCiliumEndpointCRDName)
	option.BindEnv(option.DisableCiliumEndpointCRDName)

	// Deprecated, remove in 1.9
	flags.Bool(operatorOption.EnableCEPGC, true, "Enable CiliumEndpoint garbage collector")
	option.BindEnv(operatorOption.EnableCEPGC)
	flags.MarkDeprecated(operatorOption.EnableCEPGC, fmt.Sprintf("Please use %s=0 to disable CEP GC", operatorOption.EndpointGCInterval))

	flags.Duration(operatorOption.EndpointGCInterval, operatorOption.EndpointGCIntervalDefault, "GC interval for cilium endpoints")
	option.BindEnv(operatorOption.EndpointGCInterval)

	flags.Bool(operatorOption.EnableMetrics, false, "Enable Prometheus metrics")
	option.BindEnv(operatorOption.EnableMetrics)

	var defaultIPAM string
	switch binaryName {
	case "cilium-operator":
		defaultIPAM = ipamOption.IPAMHostScopeLegacy
	case "cilium-operator-aws":
		defaultIPAM = ipamOption.IPAMENI
	case "cilium-operator-azure":
		defaultIPAM = ipamOption.IPAMAzure
	case "cilium-operator-generic":
		defaultIPAM = ipamOption.IPAMOperator
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
			case ipamOption.IPAMKubernetes, ipamOption.IPAMOperator, ipamOption.IPAMCRD:
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
		case "cilium-operator-generic":
			switch ipamFlagValue {
			case ipamOption.IPAMENI, ipamOption.IPAMAzure:
				return unsupporterErr()
			case ipamOption.IPAMHostScopeLegacy:
				return fmt.Errorf("%s, as it is deprecated, but it is still supported by legacy cilium-operator binary)", unsupporterErr().Error())
			}
		}

		return nil
	}

	flags.Duration(operatorOption.IdentityHeartbeatTimeout, 2*defaults.KVstoreLeaseTTL, "Timeout after which identity expires on lack of heartbeat")
	option.BindEnv(operatorOption.IdentityHeartbeatTimeout)

	flags.Bool(option.EnableIPv4Name, defaults.EnableIPv4, "Enable IPv4 support")
	option.BindEnv(option.EnableIPv4Name)

	flags.String(operatorOption.IPAMOperatorV4CIDR, "",
		fmt.Sprintf("IPv4 CIDR Range for Pods in cluster. Requires '%s=%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMOperator,
			option.EnableIPv4Name, "true"))
	option.BindEnv(operatorOption.IPAMOperatorV4CIDR)

	flags.Int(operatorOption.NodeCIDRMaskSizeIPv4, 24,
		fmt.Sprintf("Mask size for each IPv4 podCIDR per node. Requires '%s=%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMOperator,
			option.EnableIPv4Name, "true"))
	option.BindEnv(operatorOption.NodeCIDRMaskSizeIPv4)

	flags.Bool(option.EnableIPv6Name, defaults.EnableIPv6, "Enable IPv6 support")
	option.BindEnv(option.EnableIPv6Name)

	flags.String(operatorOption.IPAMOperatorV6CIDR, "",
		fmt.Sprintf("IPv6 CIDR Range for Pods in cluster. Requires '%s=%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMOperator,
			option.EnableIPv6Name, "true"))
	option.BindEnv(operatorOption.IPAMOperatorV6CIDR)

	flags.Int(operatorOption.NodeCIDRMaskSizeIPv6, 112,
		fmt.Sprintf("Mask size for each IPv6 podCIDR per node. Requires '%s=%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMOperator,
			option.EnableIPv6Name, "true"))
	option.BindEnv(operatorOption.NodeCIDRMaskSizeIPv6)

	flags.String(option.IdentityAllocationMode, option.IdentityAllocationModeKVstore, "Method to use for identity allocation")
	option.BindEnv(option.IdentityAllocationMode)

	flags.Duration(operatorOption.IdentityGCInterval, defaults.KVstoreLeaseTTL, "GC interval for security identities")
	option.BindEnv(operatorOption.IdentityGCInterval)

	flags.String(option.KVStore, "", "Key-value store type")
	option.BindEnv(option.KVStore)

	flags.Var(option.NewNamedMapOptions(option.KVStoreOpt, &option.Config.KVStoreOpt, nil),
		option.KVStoreOpt, "Key-value store options")
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

	flags.Duration(operatorOption.NodesGCInterval, 2*time.Minute, "GC interval for nodes store in the kvstore")
	option.BindEnv(operatorOption.NodesGCInterval)

	flags.String(operatorOption.OperatorPrometheusServeAddr, ":6942", "Address to serve Prometheus metrics")
	option.BindEnv(operatorOption.OperatorPrometheusServeAddr)

	flags.String(operatorOption.OperatorAPIServeAddr, "localhost:9234", "Address to serve API requests")
	option.BindEnv(operatorOption.OperatorAPIServeAddr)

	flags.Bool(operatorOption.SyncK8sServices, true, "Synchronize Kubernetes services to kvstore")
	option.BindEnv(operatorOption.SyncK8sServices)

	flags.Bool(operatorOption.SyncK8sNodes, true, "Synchronize Kubernetes nodes to kvstore and perform CNP GC")
	option.BindEnv(operatorOption.SyncK8sNodes)

	flags.Int(operatorOption.UnmanagedPodWatcherInterval, 15, "Interval to check for unmanaged kube-dns pods (0 to disable)")
	option.BindEnv(operatorOption.UnmanagedPodWatcherInterval)

	flags.Bool(option.Version, false, "Print version information")
	option.BindEnv(option.Version)

	// Deprecated, remove in 1.9
	flags.Uint16Var(&apiServerPort, "api-server-port", 9234, "Port on which the operator should serve API requests")
	flags.MarkDeprecated("api-server-port", fmt.Sprintf("Please use %s instead", operatorOption.OperatorAPIServeAddr))

	// Deprecated, remove in 1.9
	flags.StringVar(&operatorMetrics.Address, "metrics-address", ":6942", "Address to serve Prometheus metrics")
	flags.MarkDeprecated("metrics-address", fmt.Sprintf("Please use %s instead", operatorOption.OperatorPrometheusServeAddr))

	flags.String(option.CMDRef, "", "Path to cmdref output directory")
	flags.MarkHidden(option.CMDRef)
	option.BindEnv(option.CMDRef)

	flags.Duration(option.K8sHeartbeatTimeout, 30*time.Second, "Configures the timeout for api-server heartbeat, set to 0 to disable")
	option.BindEnv(option.K8sHeartbeatTimeout)

	viper.BindPFlags(flags)
}
