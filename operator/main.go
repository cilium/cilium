// Copyright 2018-2020 Authors of Cilium
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
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/cilium/pkg/aws/eni"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/k8s"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"

	gops "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"k8s.io/klog"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-operator")

	rootCmd = &cobra.Command{
		Use:   "cilium-operator",
		Short: "Run the cilium-operator",
		Run: func(cmd *cobra.Command, args []string) {
			runOperator(cmd)
		},
	}

	k8sAPIServer            string
	k8sKubeConfigPath       string
	kvStore                 string
	kvStoreOpts             = make(map[string]string)
	apiServerPort           uint16
	shutdownSignal          = make(chan struct{})
	synchronizeServices     bool
	enableCepGC             bool
	synchronizeNodes        bool
	enableMetrics           bool
	metricsAddress          string
	eniParallelWorkers      int64
	enableENI               bool
	eniTags                 = make(map[string]string)
	awsInstanceLimitMapping = make(map[string]string)

	k8sIdentityGCInterval       time.Duration
	k8sIdentityHeartbeatTimeout time.Duration
	ciliumK8sClient             clientset.Interface

	cmdRefDir string
)

func main() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signals
		close(shutdownSignal)
	}()

	// Open socket for using gops to get stacktraces of the agent.
	if err := gops.Listen(gops.Options{}); err != nil {
		errorString := fmt.Sprintf("unable to start gops: %s", err)
		fmt.Println(errorString)
		os.Exit(-1)
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

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

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if viper.GetBool("version") {
		fmt.Printf("Cilium %s\n", version.Version)
		os.Exit(0)
	}

	option.Config.ClusterName = viper.GetString(option.ClusterName)
	option.Config.ClusterID = viper.GetInt(option.ClusterIDName)
	option.Config.DisableCiliumEndpointCRD = viper.GetBool(option.DisableCiliumEndpointCRDName)
	option.Config.K8sNamespace = viper.GetString(option.K8sNamespaceName)
	option.Config.AwsReleaseExcessIps = viper.GetBool(option.AwsReleaseExcessIps)

	viper.SetEnvPrefix("cilium")
	viper.SetConfigName("cilium-operator")
}

func kvstoreEnabled() bool {
	if kvStore == "" {
		return false
	}

	return identityAllocationMode == option.IdentityAllocationModeKVstore ||
		synchronizeServices ||
		synchronizeNodes
}

func runOperator(cmd *cobra.Command) {
	logging.SetupLogging([]string{}, map[string]string{}, "cilium-operator", viper.GetBool("debug"))

	if cmdRefDir != "" {
		// Remove the line 'Auto generated by spf13/cobra on ...'
		cmd.DisableAutoGenTag = true
		if err := doc.GenMarkdownTreeCustom(cmd, cmdRefDir, filePrepend, linkHandler); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	log.Infof("Cilium Operator %s", version.Version)
	k8sInitDone := make(chan struct{})
	go startServer(fmt.Sprintf(":%d", apiServerPort), shutdownSignal, k8sInitDone)

	if enableMetrics {
		registerMetrics()
	}

	k8sClientQPSLimit := viper.GetFloat64(option.K8sClientQPSLimit)
	k8sClientBurst := viper.GetInt(option.K8sClientBurst)
	kvStore = viper.GetString(option.KVStore)
	if m := viper.GetStringMapString(option.KVStoreOpt); len(m) > 0 {
		kvStoreOpts = m
	}

	k8s.Configure(k8sAPIServer, k8sKubeConfigPath, float32(k8sClientQPSLimit), k8sClientBurst)
	if err := k8s.Init(); err != nil {
		log.WithError(err).Fatal("Unable to connect to Kubernetes apiserver")
	}
	close(k8sInitDone)

	ciliumK8sClient = k8s.CiliumClient()
	k8sversion.Update(k8s.Client())
	if !k8sversion.Capabilities().MinimalVersionMet {
		log.Fatalf("Minimal kubernetes version not met: %s < %s",
			k8sversion.Version(), k8sversion.MinimalVersionConstraint)
	}

	// Restart kube-dns as soon as possible since it helps etcd-operator to be
	// properly setup. If kube-dns is not managed by Cilium it can prevent
	// etcd from reaching out kube-dns in EKS.
	if option.Config.DisableCiliumEndpointCRD {
		log.Infof("KubeDNS unmanaged pods controller disabled as %q option is set to 'disabled' in Cilium ConfigMap", option.DisableCiliumEndpointCRDName)
	} else if unmanagedKubeDnsWatcherInterval != 0 {
		enableUnmanagedKubeDNSController()
	}

	enableENI = viper.GetString(option.IPAM) == option.IPAMENI
	if enableENI {
		if err := eni.UpdateLimitsFromUserDefinedMappings(awsInstanceLimitMapping); err != nil {
			log.WithError(err).Fatal("Parse aws-instance-limit-mapping failed")
		}
		if viper.GetBool(option.UpdateEC2AdapterLimitViaAPI) {
			if err := eni.UpdateLimitsFromEC2API(context.TODO()); err != nil {
				log.WithError(err).Error("Unable to update instance type to adapter limits from EC2 API")
			}
		}
		awsClientQPSLimit := viper.GetFloat64(option.AWSClientQPSLimit)
		awsClientBurst := viper.GetInt(option.AWSClientBurst)
		if m := viper.GetStringMapString(option.ENITags); len(m) > 0 {
			eniTags = m
		}
		if err := startENIAllocator(awsClientQPSLimit, awsClientBurst, eniTags); err != nil {
			log.WithError(err).Fatal("Unable to start ENI allocator")
		}

		startSynchronizingCiliumNodes()
	}

	if kvstoreEnabled() {
		if synchronizeServices {
			startSynchronizingServices()
		}

		var goopts *kvstore.ExtraOptions
		scopedLog := log.WithFields(logrus.Fields{
			"kvstore": kvStore,
			"address": kvStoreOpts[fmt.Sprintf("%s.address", kvStore)],
		})
		if synchronizeServices {
			// If K8s is enabled we can do the service translation automagically by
			// looking at services from k8s and retrieve the service IP from that.
			// This makes cilium to not depend on kube dns to interact with etcd
			if k8s.IsEnabled() && kvstore.IsEtcdOperator(kvStore, kvStoreOpts, option.Config.K8sNamespace) {
				// Wait services and endpoints cache are synced with k8s before setting
				// up etcd so we can perform the name resolution for etcd-operator
				// to the service IP as well perform the service -> backend IPs for
				// that service IP.

				scopedLog.Info("cilium-operator running with service synchronization: automatic etcd service translation enabled")
				log := log.WithField(logfields.LogSubsys, "etcd")
				scopedLog.Info("Waiting for all services to be synced with kubernetes before connecting to etcd")
				<-k8sSvcCacheSynced
				scopedLog.Info("Kubernetes services synced")
				goopts = &kvstore.ExtraOptions{
					DialOption: []grpc.DialOption{
						grpc.WithDialer(k8s.CreateCustomDialer(&k8sSvcCache, log)),
					},
				}
			}
		} else {
			scopedLog.Info("cilium-operator running without service synchronization: automatic etcd service translation disabled")
		}
		scopedLog.Info("Connecting to kvstore...")
		if err := kvstore.Setup(context.TODO(), kvStore, kvStoreOpts, goopts); err != nil {
			scopedLog.WithError(err).Fatal("Unable to setup kvstore")
		}

		if synchronizeNodes {
			if err := runNodeWatcher(); err != nil {
				log.WithError(err).Error("Unable to setup node watcher")
			}
		}

		startKvstoreWatchdog()
	}

	switch identityAllocationMode {
	case option.IdentityAllocationModeCRD:
		startManagingK8sIdentities()

		if identityGCInterval != time.Duration(0) {
			go startCRDIdentityGC()
		}
	case option.IdentityAllocationModeKVstore:
		if identityGCInterval != time.Duration(0) {
			startKvstoreIdentityGC()
		}
	}

	if enableCepGC {
		enableCiliumEndpointSyncGC()
	}

	err := enableCNPWatcher()
	if err != nil {
		log.WithError(err).WithField("subsys", "CNPWatcher").Fatal(
			"Cannot connect to Kubernetes apiserver ")
	}

	err = enableCCNPWatcher()
	if err != nil {
		log.WithError(err).WithField("subsys", "CCNPWatcher").Fatal(
			"Cannot connect to Kubernetes apiserver ")
	}

	log.Info("Initialization complete")

	<-shutdownSignal
	// graceful exit
	log.Info("Received termination signal. Shutting down")
	return
}
