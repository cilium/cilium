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
	"time"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
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
	operatorOption.Config.Populate()

	// add hooks after setting up metrics in the option.Confog
	logging.DefaultLogger.Hooks.Add(metrics.NewLoggingHook(components.CiliumOperatortName))

	// Logging should always be bootstrapped first. Do not add any code above this!
	logging.SetupLogging(option.Config.LogDriver, logging.LogOptions(option.Config.LogOpt), "cilium-operator", option.Config.Debug)

	option.LogRegisteredOptions(log)
}

func main() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGINT, unix.SIGTERM)

	go func() {
		<-signals
		gops.Close()
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
		operatorOption.Config.SyncK8sServices ||
		operatorOption.Config.SyncK8sNodes
}

func getAPIServerAddr() []string {
	if operatorOption.Config.OperatorAPIServeAddr == "" {
		return []string{fmt.Sprintf("127.0.0.1:%d", apiServerPort), fmt.Sprintf("[::1]:%d", apiServerPort)}
	}
	return []string{operatorOption.Config.OperatorAPIServeAddr}
}

func runOperator(cmd *cobra.Command) {
	log.Infof("Cilium Operator %s", version.Version)
	k8sInitDone := make(chan struct{})
	go startServer(shutdownSignal, k8sInitDone, getAPIServerAddr()...)

	if operatorOption.Config.EnableMetrics {
		operatorMetrics.Register()
	}

	k8s.Configure(
		option.Config.K8sAPIServer,
		option.Config.K8sKubeConfigPath,
		float32(option.Config.K8sClientQPSLimit),
		option.Config.K8sClientBurst,
	)
	if err := k8s.Init(option.Config); err != nil {
		log.WithError(err).Fatal("Unable to connect to Kubernetes apiserver")
	}
	close(k8sInitDone)

	ciliumK8sClient = k8s.CiliumClient()
	k8sversion.Update(k8s.Client(), option.Config)
	if !k8sversion.Capabilities().MinimalVersionMet {
		log.Fatalf("Minimal kubernetes version not met: %s < %s",
			k8sversion.Version(), k8sversion.MinimalVersionConstraint)
	}

	// Restart kube-dns as soon as possible since it helps etcd-operator to be
	// properly setup. If kube-dns is not managed by Cilium it can prevent
	// etcd from reaching out kube-dns in EKS.
	if option.Config.DisableCiliumEndpointCRD {
		log.Infof("KubeDNS unmanaged pods controller disabled as %q option is set to 'disabled' in Cilium ConfigMap", option.DisableCiliumEndpointCRDName)
	} else if operatorOption.Config.UnmanagedPodWatcherInterval != 0 {
		go enableUnmanagedKubeDNSController()
	}

	var (
		nodeManager *allocator.NodeEventHandler
		err         error
	)
	switch ipamMode := option.Config.IPAM; ipamMode {
	case ipamOption.IPAMAzure, ipamOption.IPAMENI, ipamOption.IPAMOperator:
		alloc, providerBuiltin := allocatorProviders[ipamMode]
		if !providerBuiltin {
			log.Fatalf("%s allocator is not supported by this version of cilium-operator", ipamMode)
		}

		if err := alloc.Init(); err != nil {
			log.WithError(err).Fatalf("Unable to init %s allocator", ipamMode)
		}

		nm, err := alloc.Start(&ciliumNodeUpdateImplementation{})
		if err != nil {
			log.WithError(err).Fatalf("Unable to start %s allocator", ipamMode)
		}

		startSynchronizingCiliumNodes(nm)
		nodeManager = &nm

		switch ipamMode {
		case ipamOption.IPAMOperator:
			// We will use CiliumNodes as the source of truth for the podCIDRs.
			// Once the CiliumNodes are synchronized with the operator we will
			// be able to watch for K8s Node events which they will be used
			// to create the remaining CiliumNodes.
			<-k8sCiliumNodesCacheSynced

			// We don't want CiliumNodes that don't have podCIDRs to be
			// allocated with a podCIDR already being used by another node.
			// For this reason we will call Resync after all CiliumNodes are
			// synced with the operator to signal the node manager, since it
			// knows all podCIDRs that are currently set in the cluster, that
			// it can allocate podCIDRs for the nodes that don't have a podCIDR
			// set.
			nm.Resync(context.Background(), time.Time{})
		}
	}

	if kvstoreEnabled() {
		if operatorOption.Config.SyncK8sServices {
			startSynchronizingServices()
		}

		var goopts *kvstore.ExtraOptions
		scopedLog := log.WithFields(logrus.Fields{
			"kvstore": option.Config.KVStore,
			"address": option.Config.KVStoreOpt[fmt.Sprintf("%s.address", option.Config.KVStore)],
		})
		if operatorOption.Config.SyncK8sServices {
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
							slimSvcObj := k8s.ConvertToK8sService(k8sSvc)
							slimSvc := k8s.ObjToV1Services(slimSvcObj)
							if slimSvc == nil {
								// This will never happen but still log it
								scopedLog.Warnf("BUG: invalid k8s service: %s", slimSvcObj)
							}
							sc.UpdateService(slimSvc, nil)
							svcGetter = &serviceGetter{
								shortCutK8sCache: &sc,
								k8sCache:         &k8sSvcCache,
							}
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

		if operatorOption.Config.SyncK8sNodes {
			if err := runNodeWatcher(nodeManager); err != nil {
				log.WithError(err).Error("Unable to setup node watcher")
			}
		}

		startKvstoreWatchdog()
	}

	switch option.Config.IdentityAllocationMode {
	case option.IdentityAllocationModeCRD:
		if !k8s.IsEnabled() {
			log.Fatal("CRD Identity allocation mode requires k8s to be configured.")
		}

		startManagingK8sIdentities()

		if operatorOption.Config.IdentityGCInterval != 0 {
			go startCRDIdentityGC()
		}
	case option.IdentityAllocationModeKVstore:
		if operatorOption.Config.IdentityGCInterval != 0 {
			startKvstoreIdentityGC()
		}
	}

	if operatorOption.Config.EnableCEPGC && operatorOption.Config.EndpointGCInterval != 0 {
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
}
