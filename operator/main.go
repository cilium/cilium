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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/cilium/pkg/aws/eni"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/k8s"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/types"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/version"

	gops "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-operator")

	leaderElectionResourceLockName = "cilium-operator-resource-lock"

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

	// identityRateLimiter is a rate limiter to rate limit the number of
	// identities being GCed by the operator. See the documentation of
	// rate.Limiter to understand its difference than 'x/time/rate.Limiter'.
	//
	// With our rate.Limiter implementation Cilium will be able to handle bursts
	// of identities being garbage collected with the help of the functionality
	// provided by the 'policy-trigger-interval' in the cilium-agent. With the
	// policy-trigger even if we receive N identity changes over the interval
	// set, Cilium will only need to process all of them at once instead of
	// processing each one individually.
	identityRateLimiter *rate.Limiter

	// Use a Go context so we can tell the leaderelection code when we
	// want to step down
	leaderElectionCtx, leaderElectionCtxCancel = context.WithCancel(context.Background())

	// isLeader is an atomic boolean value that is true when the Operator is
	// elected leader. Otherwise, it is false.
	isLeader atomic.Value
)

func doCleanup() {
	isLeader.Store(false)
	gops.Close()
	close(shutdownSignal)
	leaderElectionCtxCancel()
	os.Exit(0)
}

func main() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signals
		doCleanup()
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
	flags.Duration(option.IdentityGCRateInterval, time.Minute,
		"Interval used for rate limiting the GC of security identities")
	option.BindEnv(option.IdentityGCRateInterval)
	flags.Int64(option.IdentityGCRateLimit, 250,
		fmt.Sprintf("Maximum number of security identities that will be deleted within the %s", option.IdentityGCRateInterval))
	option.BindEnv(option.IdentityGCRateLimit)
	flags.DurationVar(&kvNodeGCInterval, "nodes-gc-interval", time.Minute*2, "GC interval for nodes store in the kvstore")
	flags.Int64Var(&eniParallelWorkers, "eni-parallel-workers", defaults.ENIParallelWorkers, "Maximum number of parallel workers used by ENI allocator")
	flags.Bool(option.K8sEnableAPIDiscovery, defaults.K8sEnableAPIDiscovery, "Enable discovery of Kubernetes API groups and resources with the discovery API")
	option.BindEnv(option.K8sEnableAPIDiscovery)
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

	flags.String(option.EC2APIEndpoint, "", "AWS API endpoint for the EC2 service")
	option.BindEnv(option.EC2APIEndpoint)

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

	flags.Duration(option.K8sHeartbeatTimeout, 30*time.Second, "Configures the timeout for api-server heartbeat, set to 0 to disable")
	option.BindEnv(option.K8sHeartbeatTimeout)

	flags.Duration(option.LeaderElectionLeaseDuration, 15*time.Second,
		"Duration that non-leader operator candidates will wait before forcing to acquire leadership")
	option.BindEnv(option.LeaderElectionLeaseDuration)

	flags.Duration(option.LeaderElectionRenewDeadline, 10*time.Second,
		"Duration that current acting master will retry refreshing leadership in before giving up the lock")
	option.BindEnv(option.LeaderElectionRenewDeadline)

	flags.Duration(option.LeaderElectionRetryPeriod, 2*time.Second,
		"Duration that LeaderElector clients should wait between retries of the actions")
	option.BindEnv(option.LeaderElectionRetryPeriod)

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
	option.Config.EC2APIEndpoint = viper.GetString(option.EC2APIEndpoint)
	option.Config.IdentityGCRateInterval = viper.GetDuration(option.IdentityGCRateInterval)
	option.Config.IdentityGCRateLimit = viper.GetInt64(option.IdentityGCRateLimit)
	option.Config.LeaderElectionLeaseDuration = viper.GetDuration(option.LeaderElectionLeaseDuration)
	option.Config.LeaderElectionRenewDeadline = viper.GetDuration(option.LeaderElectionRenewDeadline)
	option.Config.LeaderElectionRetryPeriod = viper.GetDuration(option.LeaderElectionRetryPeriod)

	// Enable fallback to direct API probing to check for support of Leases in
	// case Discovery API fails.
	option.Config.EnableK8sLeasesFallbackDiscovery()

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

func getAPIServerAddr() []string {
	return []string{fmt.Sprintf("127.0.0.1:%d", apiServerPort), fmt.Sprintf("[::1]:%d", apiServerPort)}
}

// runOperator implements the logic of leader election for cilium-operator using
// built-in leader election capbility in kubernetes.
// See: https://github.com/kubernetes/client-go/blob/master/examples/leader-election/main.go
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
	isLeader.Store(false)
	go startServer(shutdownSignal, k8sInitDone, getAPIServerAddr()...)

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
	if err := k8s.Init(option.Config); err != nil {
		log.WithError(err).Fatal("Unable to connect to Kubernetes apiserver")
	}
	close(k8sInitDone)

	ciliumK8sClient = k8s.CiliumClient()
	k8sversion.Update(k8s.Client(), option.Config)
	capabilities := k8sversion.Capabilities()

	if !capabilities.MinimalVersionMet {
		log.Fatalf("Minimal kubernetes version not met: %s < %s",
			k8sversion.Version(), k8sversion.MinimalVersionConstraint)
	}

	// We only support Operator in HA mode for Kubernetes Versions having support for
	// LeasesResourceLock.
	// See docs on capabilities.LeasesResourceLock for more context.
	if !capabilities.LeasesResourceLock {
		log.Info("Support for coordination.k8s.io/v1 not present, fallback to non HA mode")
		onOperatorStartLeading(leaderElectionCtx)
		return
	}

	// Get hostname for identity name of the lease lock holder.
	// We identify the leader of the operator cluster using hostname.
	operatorID, err := os.Hostname()
	if err != nil {
		log.WithError(err).Fatal("Failed to get hostname when generating lease lock identity")
	}
	operatorID = testutils.RandomStringWithPrefix(operatorID+"-", 10)

	ns := option.Config.K8sNamespace
	// If due to any reason the CILIUM_K8S_NAMESPACE is not set we assume the operator
	// to be in default namespace.
	if ns == "" {
		ns = metav1.NamespaceDefault
	}

	leResourceLock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      leaderElectionResourceLockName,
			Namespace: ns,
		},
		Client: k8s.Client().CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			// Identity name of the lock holder
			Identity: operatorID,
		},
	}

	// Start the leader election for running cilium-operators
	leaderelection.RunOrDie(leaderElectionCtx, leaderelection.LeaderElectionConfig{
		Name: leaderElectionResourceLockName,

		Lock:            leResourceLock,
		ReleaseOnCancel: true,

		LeaseDuration: option.Config.LeaderElectionLeaseDuration,
		RenewDeadline: option.Config.LeaderElectionRenewDeadline,
		RetryPeriod:   option.Config.LeaderElectionRetryPeriod,

		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: onOperatorStartLeading,
			OnStoppedLeading: func() {
				log.WithField("operator-id", operatorID).Info("Leader election lost")
				// Cleanup everything here, and exit.
				doCleanup()
			},
			OnNewLeader: func(identity string) {
				if identity == operatorID {
					log.Info("Leading the operator HA deployment")
				} else {
					log.WithField("operator-id", operatorID).Infof("Operator with ID %q elected as new leader", identity)
				}
			},
		},
	})
}

// onOperatorStartLeading is the function called once the operator starts leading
// in HA mode.
func onOperatorStartLeading(ctx context.Context) {
	isLeader.Store(true)

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
			if k8s.IsEnabled() {
				svcURL, isETCDOperator := kvstore.IsEtcdOperator(kvStore, kvStoreOpts, option.Config.K8sNamespace)
				if isETCDOperator {
					scopedLog.Info("cilium-operator running with service synchronization: automatic etcd service translation enabled")

					svcGetter := k8s.ServiceIPGetter(&k8sSvcCache)

					name, namespace, err := kvstore.SplitK8sServiceURL(svcURL)
					if err != nil {
						// If we couldn't derive the name/namespace for the given
						// svcURL log the error so the user can see it.
						// k8s.CreateCustomDialer won't be able to derive
						// the name/namespace as well so it does not matter that
						// we wait for all services to be synchronized with k8s.
						scopedLog.WithError(err).WithFields(logrus.Fields{
							"url": svcURL,
						}).Error("Unable to derive service name from given url")
					} else {
						scopedLog.WithFields(logrus.Fields{
							logfields.ServiceName:      name,
							logfields.ServiceNamespace: namespace,
						}).Info("Retrieving service spec from k8s to perform automatic etcd service translation")
						k8sSvc, err := k8s.Client().CoreV1().Services(namespace).Get(name, metav1.GetOptions{})
						switch {
						case err == nil:
							// Create another service cache that contains the
							// k8s service for etcd. As soon the k8s caches are
							// synced, this hijack will stop happening.
							sc := k8s.NewServiceCache()
							sc.UpdateService(&types.Service{Service: k8sSvc}, nil)
							svcGetter = &serviceGetter{
								shortCutK8sCache: &sc,
								k8sCache:         &k8sSvcCache,
							}
							break
						case errors.IsNotFound(err):
							scopedLog.Error("Service not found in k8s")
						default:
							scopedLog.Warning("Unable to get service spec from k8s, this might cause network disruptions with etcd")
						}
					}

					log := log.WithField(logfields.LogSubsys, "etcd")
					goopts = &kvstore.ExtraOptions{
						DialOption: []grpc.DialOption{
							grpc.WithDialer(k8s.CreateCustomDialer(svcGetter, log)),
						},
					}
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

	if identityGCInterval != time.Duration(0) {
		identityRateLimiter = rate.NewLimiter(
			option.Config.IdentityGCRateInterval,
			option.Config.IdentityGCRateLimit,
		)
	}

	switch identityAllocationMode {
	case option.IdentityAllocationModeCRD:
		if !k8s.IsEnabled() {
			log.Fatal("CRD Identity allocation mode requires k8s to be configured.")
		}

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
