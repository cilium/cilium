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
	"fmt"
	"os"
	"os/signal"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	"github.com/cilium/cilium/pkg/aws/eni"
	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/types"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"

	gops "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-operator")

	rootCmd = &cobra.Command{
		Use:   "cilium-operator",
		Short: "Run the cilium-operator",
		Run: func(cmd *cobra.Command, args []string) {
			cmdRefDir := viper.GetString(option.CMDRef)
			if cmdRefDir != "" {
				genMarkdown(cmd, cmdRefDir)
				os.Exit(0)
			}
			initEnv()
			runOperator(cmd)
		},
	}

	// Deprecated: remove in 1.9
	apiServerPort  uint16
	shutdownSignal = make(chan struct{})

	ciliumK8sClient clientset.Interface
)

func initEnv() {
	// Prepopulate option.Config with options from CLI.
	option.Config.Populate()

	// add hooks after setting up metrics in the option.Confog
	logging.DefaultLogger.Hooks.Add(metrics.NewLoggingHook(components.CiliumOperatortName))

	// Logging should always be bootstrapped first. Do not add any code above this!
	logging.SetupLogging(option.Config.LogDriver, option.Config.LogOpt, "cilium-operator", option.Config.Debug)

	option.LogRegisteredOptions(log)
}

func main() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGINT, unix.SIGTERM)

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

func kvstoreEnabled() bool {
	if option.Config.KVStore == "" {
		return false
	}

	return option.Config.IdentityAllocationMode == option.IdentityAllocationModeKVstore ||
		option.Config.SyncK8sServices ||
		option.Config.SyncK8sNodes
}

func getAPIServerAddr() []string {
	if option.Config.OperatorAPIServeAddr == "" {
		return []string{fmt.Sprintf("127.0.0.1:%d", apiServerPort), fmt.Sprintf("[::1]:%d", apiServerPort)}
	}
	return []string{option.Config.OperatorAPIServeAddr}
}

func runOperator(cmd *cobra.Command) {

	log.Infof("Cilium Operator %s", version.Version)
	k8sInitDone := make(chan struct{})
	go startServer(shutdownSignal, k8sInitDone, getAPIServerAddr()...)

	if option.Config.EnableMetrics {
		operatorMetrics.Register()
	}

	k8s.Configure(
		option.Config.K8sAPIServer,
		option.Config.K8sKubeConfigPath,
		float32(option.Config.K8sClientQPSLimit),
		option.Config.K8sClientBurst,
	)
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
	} else if option.Config.UnmanagedPodWatcherInterval != 0 {
		enableUnmanagedKubeDNSController()
	}

	var (
		nodeManager *ipam.NodeManager
		err         error
	)

	switch option.Config.IPAM {
	case option.IPAMENI:
		if err := eni.UpdateLimitsFromUserDefinedMappings(option.Config.AwsInstanceLimitMapping); err != nil {
			log.WithError(err).Fatal("Parse aws-instance-limit-mapping failed")
		}
		if option.Config.UpdateEC2AdapterLimitViaAPI {
			if err := eni.UpdateLimitsFromEC2API(context.TODO()); err != nil {
				log.WithError(err).Error("Unable to update instance type to adapter limits from EC2 API")
			}
		}
		nodeManager, err = startENIAllocator(
			option.Config.IPAMAPIQPSLimit,
			option.Config.IPAMAPIBurst,
			option.Config.ENITags)
		if err != nil {
			log.WithError(err).Fatal("Unable to start ENI allocator")
		}

		startSynchronizingCiliumNodes(nodeManager)

	case option.IPAMAzure:
		nodeManager, err = startAzureAllocator(option.Config.IPAMAPIQPSLimit, option.Config.IPAMAPIBurst)
		if err != nil {
			log.WithError(err).Fatal("Unable to start Azure allocator")
		}

		startSynchronizingCiliumNodes(nodeManager)
	}

	if kvstoreEnabled() {
		if option.Config.SyncK8sServices {
			startSynchronizingServices()
		}

		var goopts *kvstore.ExtraOptions
		scopedLog := log.WithFields(logrus.Fields{
			"kvstore": option.Config.KVStore,
			"address": option.Config.KVStoreOpt[fmt.Sprintf("%s.address", option.Config.KVStore)],
		})
		if option.Config.SyncK8sServices {
			// If K8s is enabled we can do the service translation automagically by
			// looking at services from k8s and retrieve the service IP from that.
			// This makes cilium to not depend on kube dns to interact with etcd
			if k8s.IsEnabled() {
				svcURL, isETCDOperator := kvstore.IsEtcdOperator(option.Config.KVStore, option.Config.KVStoreOpt, option.Config.K8sNamespace)
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
						k8sSvc, err := k8s.Client().CoreV1().Services(namespace).Get(context.TODO(), name, metav1.GetOptions{})
						switch {
						case err == nil:
							// Create another service cache that contains the
							// k8s service for etcd. As soon the k8s caches are
							// synced, this hijack will stop happening.
							sc := k8s.NewServiceCache(nil)
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
		if err := kvstore.Setup(context.TODO(), option.Config.KVStore, option.Config.KVStoreOpt, goopts); err != nil {
			scopedLog.WithError(err).Fatal("Unable to setup kvstore")
		}

		if option.Config.SyncK8sNodes {
			if err := runNodeWatcher(nodeManager); err != nil {
				log.WithError(err).Error("Unable to setup node watcher")
			}
		}

		startKvstoreWatchdog()
	}

	switch option.Config.IdentityAllocationMode {
	case option.IdentityAllocationModeCRD:
		startManagingK8sIdentities()

		if option.Config.IdentityGCInterval != 0 {
			go startCRDIdentityGC()
		}
	case option.IdentityAllocationModeKVstore:
		if option.Config.IdentityGCInterval != 0 {
			startKvstoreIdentityGC()
		}
	}

	if option.Config.EnableCEPGC && option.Config.EndpointGCInterval != 0 {
		enableCiliumEndpointSyncGC()
	}

	err = enableCNPWatcher()
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
