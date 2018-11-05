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
)

func main() {
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
	flags.String(option.K8sAPIServerName, "", "Kubernetes api address server (for https use --k8s-kubeconfig-path instead)")
	flags.String(option.K8sKubeConfigPathName, "", "Absolute path of the kubernetes kubeconfig file")
	flags.String(option.KVStoreName, "", "Key-value store type")
	flags.Var(option.NewNamedMapOptions(option.KVStoreOptsName, &option.Config.KVStoreOpts, nil),
		option.KVStoreOptsName, "Key-value store options")

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
	option.Config.ClusterMeshConfig = viper.GetString(option.ClusterMeshConfigName)
	option.Config.K8sAPIServer = viper.GetString(option.K8sAPIServerName)
	option.Config.K8sKubeConfigPath = viper.GetString(option.K8sKubeConfigPathName)
	option.Config.KVStoreType = viper.GetString(option.KVStoreName)

	viper.SetEnvPrefix("cilium")
	viper.SetConfigName("cilium-operator")
}

func runOperator(cmd *cobra.Command) {
	logging.SetupLogging([]string{}, map[string]string{}, "cilium-operator", viper.GetBool("debug"))

	if err := option.Config.ValidateCommon(); err != nil {
		log.Fatalf("invalid configuration: %s", err)
	}

	log.Infof("Cilium Operator %s", version.Version)

	if err := kvstore.Setup(option.Config.KVStoreType, option.Config.KVStoreOpts); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			"kvstore": option.Config.KVStoreType,
			"address": option.Config.KVStoreOpts[fmt.Sprintf("%s.address", option.Config.KVStoreType)],
		}).Fatal("Unable to setup kvstore")
	}

	k8s.Configure(option.Config.K8sAPIServer, option.Config.K8sKubeConfigPath)
	if err := k8s.Init(); err != nil {
		log.WithError(err).Fatal("Unable to connect to Kubernetes apiserver")
	}

	for {
		time.Sleep(time.Second)
	}
}
