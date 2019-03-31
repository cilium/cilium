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

	k8sAPIServer                string
	k8sKubeConfigPath           string
	kvStore                     string
	kvStoreOpts                 = make(map[string]string)
	apiServerPort               uint16
	shutdownSignal              = make(chan struct{})
	synchronizeServices         bool
	enableCepGC                 bool
	synchronizeNodes            bool
	k8sIdentityGCInterval       time.Duration
	k8sIdentityHeartbeatTimeout time.Duration
	synchronizeIdentities       bool
	ciliumK8sClient             clientset.Interface
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

	flags.BoolVar(&synchronizeServices, "synchronize-k8s-services", true, "Synchronize Kubernetes services to kvstore")
	flags.BoolVar(&synchronizeNodes, "synchronize-k8s-nodes", true, "Synchronize Kubernetes nodes to kvstore and perform CNP GC")
	flags.BoolVar(&synchronizeIdentities, "synchronize-identities", true, "Synchronize CRD backed identities to kvstore")
	// FIXME: this name conflicts with the name used for kvstore GC, and is a different default
	flags.DurationVar(&k8sIdentityGCInterval, "identity-gc-interval", 1*time.Minute, "Interval to run the identity garbage collector")
	flags.DurationVar(&k8sIdentityHeartbeatTimeout, "identity-heartbeat-timeout", 15*time.Minute, "Timeout after which identity expires on lack of heartbeat")
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

	if requiresKVstore() {
		scopedLog := log.WithFields(logrus.Fields{
			"kvstore": kvStore,
			"address": kvStoreOpts[fmt.Sprintf("%s.address", kvStore)],
		})
		scopedLog.Info("Connecting to kvstore...")
		if err := kvstore.Setup(kvStore, kvStoreOpts, nil); err != nil {
			scopedLog.WithError(err).Fatal("Unable to setup kvstore")
		}
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

	if synchronizeServices {
		startSynchronizingServices()
	}

	if synchronizeIdentities {
		startSynchronizingIdentities()
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
