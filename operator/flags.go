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
	"flag"
	"fmt"
	"time"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/klog"
)

func init() {
	cobra.OnInitialize(option.InitConfig("Cilium-Operator", "cilium-operator"))

	flags := rootCmd.Flags()

	flags.Int(option.AWSClientBurstDeprecated, defaults.IPAMAPIBurst, "")
	flags.MarkDeprecated(option.AWSClientBurstDeprecated, fmt.Sprintf("please use --%s", option.IPAMAPIBurst))

	flags.Int(option.IPAMAPIBurst, defaults.IPAMAPIBurst, "Upper burst limit when accessing external APIs")
	option.BindEnv(option.IPAMAPIBurst)

	flags.Float64(option.AWSClientQPSLimitDeprecated, defaults.IPAMAPIQPSLimit, "")
	flags.MarkDeprecated(option.AWSClientQPSLimitDeprecated, fmt.Sprintf("please use --%s", option.IPAMAPIQPSLimit))

	flags.Float64(option.IPAMAPIQPSLimit, defaults.IPAMAPIQPSLimit, "Queries per second limit when accessing external IPAM APIs")
	option.BindEnv(option.IPAMAPIQPSLimit)

	flags.String(option.AzureSubscriptionID, "", "Subscription ID to access Azure API")
	option.BindEnvWithLegacyEnvFallback(option.AzureSubscriptionID, "AZURE_SUBSCRIPTION_ID")

	flags.String(option.AzureResourceGroup, "", "Resource group to use for Azure IPAM")
	option.BindEnvWithLegacyEnvFallback(option.AzureResourceGroup, "AZURE_RESOURCE_GROUP")

	flags.Var(option.NewNamedMapOptions(option.AwsInstanceLimitMapping, &option.Config.AwsInstanceLimitMapping, nil),
		option.AwsInstanceLimitMapping,
		`Add or overwrite mappings of AWS instance limit in the form of `+
			`{"AWS instance type": "Maximum Network Interfaces","IPv4 Addresses `+
			`per Interface","IPv6 Addresses per Interface"}. cli example: `+
			`--aws-instance-limit-mapping=a1.medium=2,4,4 `+
			`--aws-instance-limit-mapping=a2.somecustomflavor=4,5,6 `+
			`configmap example: {"a1.medium": "2,4,4", "a2.somecustomflavor": "4,5,6"}`)
	option.BindEnv(option.AwsInstanceLimitMapping)

	flags.Bool(option.AwsReleaseExcessIps, false, "Enable releasing excess free IP addresses from AWS ENI.")
	option.BindEnv(option.AwsReleaseExcessIps)

	flags.Var(option.NewNamedMapOptions(option.ENITags, &option.Config.ENITags, nil),
		option.ENITags, "ENI tags in the form of k1=v1 (multiple k/v pairs can be passed by repeating the CLI flag)")
	option.BindEnv(option.ENITags)

	flags.Int64(option.ENIParallelWorkersDeprecated, defaults.ParallelAllocWorkers, "")
	flags.MarkDeprecated(option.ENIParallelWorkersDeprecated, fmt.Sprintf("please use --%s", option.ParallelAllocWorkers))
	option.BindEnv(option.ENIParallelWorkersDeprecated)

	flags.Int64(option.ParallelAllocWorkers, defaults.ParallelAllocWorkers, "Maximum number of parallel IPAM workers")
	option.BindEnv(option.ParallelAllocWorkers)

	flags.Bool(option.UpdateEC2AdapterLimitViaAPI, false, "Use the EC2 API to update the instance type to adapter limits")
	option.BindEnv(option.UpdateEC2AdapterLimitViaAPI)

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
	flags.Bool(option.EnableCCNPNodeStatusGC, true, "Enable CiliumClusterwideNetworkPolicy Status garbage collection for nodes which have been removed from the cluster")
	option.BindEnv(option.EnableCCNPNodeStatusGC)
	flags.MarkDeprecated(option.EnableCCNPNodeStatusGC, fmt.Sprintf("Please use %s=0 to disable CCNP Status GC", option.CNPNodeStatusGCInterval))

	// Deprecated, remove in 1.9
	flags.Bool(option.EnableCNPNodeStatusGC, true, "Enable CiliumNetworkPolicy Status garbage collection for nodes which have been removed from the cluster")
	option.BindEnv(option.EnableCNPNodeStatusGC)
	flags.MarkDeprecated(option.EnableCNPNodeStatusGC, fmt.Sprintf("Please use %s=0 to disable CNP Status GC", option.CNPNodeStatusGCInterval))

	flags.Duration(option.CNPNodeStatusGCInterval, 2*time.Minute, "GC interval for nodes which have been removed from the cluster in CiliumNetworkPolicy Status")
	option.BindEnv(option.CNPNodeStatusGCInterval)

	flags.Duration(option.CNPStatusUpdateInterval, 1*time.Second, "Interval between CNP status updates sent to the k8s-apiserver per-CNP")
	option.BindEnv(option.CNPStatusUpdateInterval)

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
	flags.Bool(option.EnableCEPGC, true, "Enable CiliumEndpoint garbage collector")
	option.BindEnv(option.EnableCEPGC)
	flags.MarkDeprecated(option.EnableCEPGC, fmt.Sprintf("Please use %s=0 to disable CEP GC", option.EndpointGCInterval))

	flags.Duration(option.EndpointGCInterval, 30*time.Minute, "GC interval for cilium endpoints")
	option.BindEnv(option.EndpointGCInterval)

	flags.Bool(option.EnableMetrics, false, "Enable Prometheus metrics")
	option.BindEnv(option.EnableMetrics)

	flags.String(option.IPAM, option.IPAMHostScopeLegacy, "Backend to use for IPAM")
	option.BindEnv(option.IPAM)

	flags.Duration(option.IdentityHeartbeatTimeout, 15*time.Minute, "Timeout after which identity expires on lack of heartbeat")
	option.BindEnv(option.IdentityHeartbeatTimeout)

	flags.String(option.IdentityAllocationMode, option.IdentityAllocationModeKVstore, "Method to use for identity allocation")
	option.BindEnv(option.IdentityAllocationMode)

	flags.Duration(option.IdentityGCInterval, defaults.KVstoreLeaseTTL, "GC interval for security identities")
	option.BindEnv(option.IdentityGCInterval)

	flags.String(option.KVStore, "", "Key-value store type")
	option.BindEnv(option.KVStore)

	flags.Var(option.NewNamedMapOptions(option.KVStoreOpt, &option.Config.KVStoreOpt, nil),
		option.KVStoreOpt, "Key-value store options")
	option.BindEnv(option.KVStoreOpt)

	flags.String(option.K8sAPIServer, "", "Kubernetes API server URL")
	option.BindEnv(option.K8sAPIServer)

	flags.Float32(option.K8sClientQPSLimit, defaults.K8sClientQPSLimit, "Queries per second limit for the K8s client")
	flags.Int(option.K8sClientBurst, defaults.K8sClientBurst, "Burst value allowed for the K8s client")

	flags.Bool(option.K8sEnableEndpointSlice, defaults.K8sEnableEndpointSlice, fmt.Sprintf("Enables k8s EndpointSlice feature into Cilium-Operator if the k8s cluster supports it"))
	option.BindEnv(option.K8sEnableEndpointSlice)

	flags.String(option.K8sNamespaceName, "", "Name of the Kubernetes namespace in which Cilium Operator is deployed in")
	option.BindEnv(option.K8sNamespaceName)

	flags.String(option.K8sKubeConfigPath, "", "Absolute path of the kubernetes kubeconfig file")
	option.BindEnv(option.K8sKubeConfigPath)

	flags.Duration(option.NodesGCInterval, 2*time.Minute, "GC interval for nodes store in the kvstore")
	option.BindEnv(option.NodesGCInterval)

	flags.String(option.OperatorPrometheusServeAddr, ":6942", "Address to serve Prometheus metrics")
	option.BindEnv(option.OperatorPrometheusServeAddr)

	flags.String(option.OperatorAPIServeAddr, "localhost:9234", "Address to serve API requests")
	option.BindEnv(option.OperatorAPIServeAddr)

	flags.Bool(option.SyncK8sServices, true, "Synchronize Kubernetes services to kvstore")
	option.BindEnv(option.SyncK8sServices)

	flags.Bool(option.SyncK8sNodes, true, "Synchronize Kubernetes nodes to kvstore and perform CNP GC")
	option.BindEnv(option.SyncK8sNodes)

	flags.Int(option.UnmanagedPodWatcherInterval, 15, "Interval to check for unmanaged kube-dns pods (0 to disable)")
	option.BindEnv(option.UnmanagedPodWatcherInterval)

	flags.Bool(option.Version, false, "Print version information")
	option.BindEnv(option.Version)

	// Deprecated, remove in 1.9
	flags.Uint16Var(&apiServerPort, "api-server-port", 9234, "Port on which the operator should serve API requests")
	flags.MarkDeprecated("api-server-port", fmt.Sprintf("Please use %s instead", option.OperatorAPIServeAddr))

	// Deprecated, remove in 1.9
	flags.StringVar(&operatorMetrics.Address, "metrics-address", ":6942", "Address to serve Prometheus metrics")
	flags.MarkDeprecated("metrics-address", fmt.Sprintf("Please use %s instead", option.OperatorPrometheusServeAddr))

	flags.String(option.CMDRef, "", "Path to cmdref output directory")
	flags.MarkHidden(option.CMDRef)
	option.BindEnv(option.CMDRef)

	flags.Duration(option.K8sHeartbeatTimeout, 30*time.Second, "Configures the timeout for api-server heartbeat, set to 0 to disable")
	option.BindEnv(option.K8sHeartbeatTimeout)

	viper.BindPFlags(flags)

	// Make sure that klog logging variables are initialized so that we can
	// update them from this file.
	klog.InitFlags(nil)

	// Make sure klog (used by the client-go dependency) logs to stderr, as it
	// will try to log to directories that may not exist in the cilium-operator
	// container (/tmp) and cause the cilium-operator to exit.
	flag.Set("logtostderr", "true")
}
