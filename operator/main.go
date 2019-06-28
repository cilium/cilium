// Copyright 2018-2019 Authors of Cilium
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
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	k8sAPIServer        string
	k8sKubeConfigPath   string
	kvStore             string
	kvStoreOpts         = make(map[string]string)
	apiServerPort       uint16
	shutdownSignal      = make(chan struct{})
	synchronizeServices bool
	enableCepGC         bool
	synchronizeNodes    bool
	enableMetrics       bool
	metricsAddress      string

	ciliumK8sClient clientset.Interface
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
	flags.StringVar(&k8sAPIServer, "k8s-api-server", "", "Kubernetes api address server (for https use --k8s-kubeconfig-path instead)")
	flags.StringVar(&k8sKubeConfigPath, "k8s-kubeconfig-path", "", "Absolute path of the kubernetes kubeconfig file")
	flags.StringVar(&kvStore, "kvstore", "", "Key-value store type")
	flags.Var(option.NewNamedMapOptions("kvstore-opts", &kvStoreOpts, nil), "kvstore-opt", "Key-value store options")
	flags.Uint16Var(&apiServerPort, "api-server-port", 9234, "Port on which the operator should serve API requests")
	flags.String(option.IPAM, "", "Backend to use for IPAM")
	option.BindEnv(option.IPAM)
	flags.BoolVar(&enableMetrics, "enable-metrics", false, "Enable Prometheus metrics")
	flags.StringVar(&metricsAddress, "metrics-address", ":6942", "Address to serve Prometheus metrics")
	flags.BoolVar(&synchronizeServices, "synchronize-k8s-services", true, "Synchronize Kubernetes services to kvstore")
	flags.BoolVar(&synchronizeNodes, "synchronize-k8s-nodes", true, "Synchronize Kubernetes nodes to kvstore and perform CNP GC")
	flags.BoolVar(&enableCepGC, "cilium-endpoint-gc", true, "Enable CiliumEndpoint garbage collector")
	flags.DurationVar(&identityGCInterval, "identity-gc-interval", time.Minute*10, "GC interval for security identities")
	flags.DurationVar(&kvNodeGCInterval, "nodes-gc-interval", time.Minute*2, "GC interval for nodes store in the kvstore")

	flags.IntVar(&unmanagedKubeDnsWatcherInterval, "unmanaged-pod-watcher-interval", 15, "Interval to check for unmanaged kube-dns pods (0 to disable)")

	// We need to obtain from Cilium ConfigMap if the CiliumEndpointCRD option
	// is enabled or disabled. This option is marked as hidden because the
	// Cilium Endpoint CRD controller is not in this program and by having it
	// being printed by operator --help could confuse users.
	flags.Bool(option.DisableCiliumEndpointCRDName, false, "")
	flags.MarkHidden(option.DisableCiliumEndpointCRDName)
	option.BindEnv(option.DisableCiliumEndpointCRDName)

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

	viper.SetEnvPrefix("cilium")
	viper.SetConfigName("cilium-operator")
}

func requiresKVstore() bool {
	if identityGCInterval != time.Duration(0) {
		return true
	}

	switch {
	case synchronizeServices, synchronizeNodes:
		return true
	}

	return false
}

func runOperator(cmd *cobra.Command) {
	logging.SetupLogging([]string{}, map[string]string{}, "cilium-operator", viper.GetBool("debug"))

	log.Infof("Cilium Operator %s", version.Version)
	go startServer(fmt.Sprintf(":%d", apiServerPort), shutdownSignal)

	if enableMetrics {
		registerMetrics()
	}

	k8s.Configure(k8sAPIServer, k8sKubeConfigPath)
	if err := k8s.Init(); err != nil {
		log.WithError(err).Fatal("Unable to connect to Kubernetes apiserver")
	}

	ciliumK8sClient = k8s.CiliumClient()
	k8sversion.Update(k8s.Client())
	if !k8sversion.Capabilities().MinimalVersionMet {
		log.Fatalf("Minimal kubernetes version not met: %s < %s",
			k8sversion.Version(), k8sversion.MinimalVersionConstraint)
	}

	enableENI := viper.GetString(option.IPAM) == option.IPAMENI
	if enableENI {
		if err := startENIAllocator(); err != nil {
			log.WithError(err).Fatal("Unable to start ENI allocator")
		}
	}

	if enableENI {
		startSynchronizingCiliumNodes()
	}

	if requiresKVstore() {
		var goopts *kvstore.ExtraOptions
		scopedLog := log.WithFields(logrus.Fields{
			"kvstore": kvStore,
			"address": kvStoreOpts[fmt.Sprintf("%s.address", kvStore)],
		})
		if synchronizeServices {
			// If K8s is enabled we can do the service translation automagically by
			// looking at services from k8s and retrieve the service IP from that.
			// This makes cilium to not depend on kube dns to interact with etcd
			if k8s.IsEnabled() && kvstore.IsEtcdOperator(option.Config.KVStore, option.Config.KVStoreOpt, option.Config.K8sNamespace) {
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
						grpc.WithDialer(func(s string, duration time.Duration) (conn net.Conn, e error) {
							// If the service is available, do the service translation to
							// the service IP. Otherwise dial with the original service
							// name `s`.
							svc := k8s.ParseServiceIDFrom(s)
							if svc != nil {
								backendIP := k8sSvcCache.GetRandomBackendIP(*svc)
								if backendIP != nil {
									s = backendIP.String()
								}
							} else {
								log.Debug("Service not found")
							}
							log.Debugf("custom dialer based on k8s service backend is dialing to %q", s)
							return net.Dial("tcp", s)
						},
						),
					},
				}
			}
		} else {
			scopedLog.Info("cilium-operator running without service synchronization: automatic etcd service translation disabled")
		}
		scopedLog.Info("Connecting to kvstore...")
		if err := kvstore.Setup(kvStore, kvStoreOpts, goopts); err != nil {
			scopedLog.WithError(err).Fatal("Unable to setup kvstore")
		}
	}

	if synchronizeServices {
		startSynchronizingServices()
	}

	if enableCepGC {
		enableCiliumEndpointSyncGC()
	}

	if synchronizeNodes {
		if err := runNodeWatcher(); err != nil {
			log.WithError(err).Error("Unable to setup node watcher")
		}
	}

	if identityGCInterval != time.Duration(0) {
		startIdentityGC()
	}

	if option.Config.DisableCiliumEndpointCRD {
		log.Infof("KubeDNS unmanaged pods controller disabled as %q option is set to 'disabled' in Cilium ConfigMap", option.DisableCiliumEndpointCRDName)
	} else {
		enableUnmanagedKubeDNSController()
	}

	err := enableCNPWatcher()
	if err != nil {
		log.WithError(err).WithField("subsys", "CNPWatcher").Fatal(
			"Cannot connect to Kubernetes apiserver ")
	}

	log.Info("Initialization complete")

	<-shutdownSignal
	// graceful exit
	log.Info("Received termination signal. Shutting down")
	return
}
