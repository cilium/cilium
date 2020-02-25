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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/klog"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	cobra.OnInitialize(initConfig)

	flags := rootCmd.Flags()
	flags.Bool("version", false, "Print version information")
	flags.Int(option.ClusterIDName, 0, "Unique identifier of the cluster")
	option.BindEnv(option.ClusterIDName)
	flags.String(option.ClusterName, defaults.ClusterName, "Name of the cluster")
	option.BindEnv(option.ClusterName)
	flags.BoolP("debug", "D", false, "Enable debugging mode")
	flags.StringVar(&k8sAPIServer, "k8s-api-server", "", "Kubernetes API server URL")
	flags.StringVar(&k8sKubeConfigPath, "k8s-kubeconfig-path", "", "Absolute path of the kubernetes kubeconfig file")
	flags.String(option.KVStore, "", "Key-value store type")
	option.BindEnv(option.KVStore)
	flags.Var(option.NewNamedMapOptions(option.KVStoreOpt, &kvStoreOpts, nil), option.KVStoreOpt, "Key-value store options")
	option.BindEnv(option.KVStoreOpt)
	flags.Uint16Var(&apiServerPort, "api-server-port", 9234, "Port on which the operator should serve API requests")
	flags.String(option.IPAM, "", "Backend to use for IPAM")
	option.BindEnv(option.IPAM)
	flags.Bool(option.AwsReleaseExcessIps, false, "Enable releasing excess free IP addresses from AWS ENI.")
	option.BindEnv(option.AwsReleaseExcessIps)
	flags.BoolVar(&enableMetrics, "enable-metrics", false, "Enable Prometheus metrics")
	flags.StringVar(&metricsAddress, "metrics-address", ":6942", "Address to serve Prometheus metrics")
	flags.BoolVar(&synchronizeServices, "synchronize-k8s-services", true, "Synchronize Kubernetes services to kvstore")
	flags.BoolVar(&synchronizeNodes, "synchronize-k8s-nodes", true, "Synchronize Kubernetes nodes to kvstore and perform CNP GC")
	flags.DurationVar(&k8sIdentityHeartbeatTimeout, "identity-heartbeat-timeout", 15*time.Minute, "Timeout after which identity expires on lack of heartbeat")
	flags.BoolVar(&enableCepGC, "cilium-endpoint-gc", true, "Enable CiliumEndpoint garbage collector")
	flags.DurationVar(&ciliumEndpointGCInterval, "cilium-endpoint-gc-interval", time.Minute*30, "GC interval for cilium endpoints")
	flags.StringVar(&identityAllocationMode, option.IdentityAllocationMode, option.IdentityAllocationModeKVstore, "Method to use for identity allocation")
	option.BindEnv(option.IdentityAllocationMode)
	flags.DurationVar(&identityGCInterval, "identity-gc-interval", defaults.KVstoreLeaseTTL, "GC interval for security identities")
	flags.DurationVar(&kvNodeGCInterval, "nodes-gc-interval", time.Minute*2, "GC interval for nodes store in the kvstore")
	flags.Int64Var(&eniParallelWorkers, "eni-parallel-workers", defaults.ENIParallelWorkers, "Maximum number of parallel workers used by ENI allocator")
	flags.String(option.K8sNamespaceName, "", "Name of the Kubernetes namespace in which Cilium Operator is deployed in")
	option.BindEnv(option.K8sNamespaceName)
	flags.Bool(option.K8sEnableEndpointSlice, defaults.K8sEnableEndpointSlice, fmt.Sprintf("Enables k8s EndpointSlice feature into Cilium-Operator if the k8s cluster supports it"))
	option.BindEnv(option.K8sEnableEndpointSlice)

	flags.IntVar(&unmanagedKubeDnsWatcherInterval, "unmanaged-pod-watcher-interval", 15, "Interval to check for unmanaged kube-dns pods (0 to disable)")

	flags.Int(option.AWSClientBurst, defaults.AWSClientBurst, "Burst value allowed for the AWS client used by the AWS ENI IPAM")
	flags.Float64(option.AWSClientQPSLimit, defaults.AWSClientQPSLimit, "Queries per second limit for the AWS client used by the AWS ENI IPAM")
	flags.Var(option.NewNamedMapOptions(option.ENITags, &eniTags, nil), option.ENITags, "ENI tags in the form of k1=v1 (multiple k/v pairs can be passed by repeating the CLI flag)")
	flags.Var(option.NewNamedMapOptions(option.AwsInstanceLimitMapping, &awsInstanceLimitMapping, nil),
		option.AwsInstanceLimitMapping, "Add or overwrite mappings of AWS instance limit in the form of {\"AWS instance type\": \"Maximum Network Interfaces\",\"IPv4 Addresses per Interface\",\"IPv6 Addresses per Interface\"}. cli example: --aws-instance-limit-mapping=a1.medium=2,4,4 --aws-instance-limit-mapping=a2.somecustomflavor=4,5,6 configmap example: {\"a1.medium\": \"2,4,4\", \"a2.somecustomflavor\": \"4,5,6\"}")
	option.BindEnv(option.AwsInstanceLimitMapping)
	flags.Bool(option.UpdateEC2AdapterLimitViaAPI, false, "Use the EC2 API to update the instance type to adapter limits")

	flags.Float32(option.K8sClientQPSLimit, defaults.K8sClientQPSLimit, "Queries per second limit for the K8s client")
	flags.Int(option.K8sClientBurst, defaults.K8sClientBurst, "Burst value allowed for the K8s client")

	// We need to obtain from Cilium ConfigMap if the CiliumEndpointCRD option
	// is enabled or disabled. This option is marked as hidden because the
	// Cilium Endpoint CRD controller is not in this program and by having it
	// being printed by operator --help could confuse users.
	flags.Bool(option.DisableCiliumEndpointCRDName, false, "")
	flags.MarkHidden(option.DisableCiliumEndpointCRDName)
	option.BindEnv(option.DisableCiliumEndpointCRDName)

	flags.BoolVar(&enableCNPNodeStatusGC, "cnp-node-status-gc", true, "Enable CiliumNetworkPolicy Status garbage collection for nodes which have been removed from the cluster")
	flags.BoolVar(&enableCCNPNodeStatusGC, "ccnp-node-status-gc", true, "Enable CiliumClusterwideNetworkPolicy Status garbage collection for nodes which have been removed from the cluster")
	flags.DurationVar(&ciliumCNPNodeStatusGCInterval, "cnp-node-status-gc-interval", time.Minute*2, "GC interval for nodes which have been removed from the cluster in CiliumNetworkPolicy Status")

	flags.DurationVar(&cnpStatusUpdateInterval, "cnp-status-update-interval", 1*time.Second, "interval between CNP status updates sent to the k8s-apiserver per-CNP")

	flags.StringVar(&cmdRefDir, "cmdref", "", "Path to cmdref output directory")
	flags.MarkHidden("cmdref")
	viper.BindPFlags(flags)

	// Make sure that klog logging variables are initialized so that we can
	// update them from this file.
	klog.InitFlags(nil)

	// Make sure klog (used by the client-go dependency) logs to stderr, as it
	// will try to log to directories that may not exist in the cilium-operator
	// container (/tmp) and cause the cilium-operator to exit.
	flag.Set("logtostderr", "true")
}
