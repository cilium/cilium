// Copyright 2018 Authors of Cilium
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
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"

	gops "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	shutdownSignal      = make(chan bool, 1)
	synchronizeServices bool
)

func main() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signals
		shutdownSignal <- true
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
	viper.BindEnv(option.ClusterIDName, option.ClusterIDEnv)
	flags.String(option.ClusterName, defaults.ClusterName, "Name of the cluster")
	viper.BindEnv(option.ClusterName, option.ClusterNameEnv)
	flags.BoolP("debug", "D", false, "Enable debugging mode")
	flags.StringVar(&k8sAPIServer, "k8s-api-server", "", "Kubernetes api address server (for https use --k8s-kubeconfig-path instead)")
	flags.StringVar(&k8sKubeConfigPath, "k8s-kubeconfig-path", "", "Absolute path of the kubernetes kubeconfig file")
	flags.StringVar(&kvStore, "kvstore", "", "Key-value store type")
	flags.Var(option.NewNamedMapOptions("kvstore-opts", &kvStoreOpts, nil), "kvstore-opt", "Key-value store options")

	flags.BoolVar(&synchronizeServices, "synchronize-k8s-services", true, "Synchronize Kubernetes services to kvstore")

	viper.BindPFlags(flags)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if viper.GetBool("version") {
		fmt.Printf("Cilium %s\n", version.Version)
		os.Exit(0)
	}

	option.Config.ClusterName = viper.GetString(option.ClusterName)
	option.Config.ClusterID = viper.GetInt(option.ClusterIDName)

	viper.SetEnvPrefix("cilium")
	viper.SetConfigName("cilium-operator")
}

func runOperator(cmd *cobra.Command) {
	logging.SetupLogging([]string{}, map[string]string{}, "cilium-operator", viper.GetBool("debug"))

	log.Infof("Cilium Operator %s", version.Version)

	if err := kvstore.Setup(kvStore, kvStoreOpts); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			"kvstore": kvStore,
			"address": kvStoreOpts[fmt.Sprintf("%s.address", kvStore)],
		}).Fatal("Unable to setup kvstore")
	}

	k8s.Configure(k8sAPIServer, k8sKubeConfigPath)
	if err := k8s.Init(); err != nil {
		log.WithError(err).Fatal("Unable to connect to Kubernetes apiserver")
	}

	startSynchronizingServices()

	err := enableCNPWatcher()
	if err != nil {
		log.WithError(err).WithField("subsys", "CNPWatcher").Fatal(
			"Cannot connect to Kubernetes apiserver ")
	}

	for {
		select {
		case <-shutdownSignal:
			// graceful exit
			log.Info("Received termination signal. Shutting down")
			return
		case <-time.After(time.Second):
		}
	}
}
