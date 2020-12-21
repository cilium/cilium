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
	"path/filepath"
	"sync/atomic"
	"time"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	operatorWatchers "github.com/cilium/cilium/operator/watchers"
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
	"github.com/cilium/cilium/pkg/rand"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/version"

	gops "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

var (
	leaderElectionResourceLockName = "cilium-operator-resource-lock"

	binaryName = filepath.Base(os.Args[0])

	log = logging.DefaultLogger.WithField(logfields.LogSubsys, binaryName)

	rootCmd = &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
		Run: func(cmd *cobra.Command, args []string) {
			cmdRefDir := viper.GetString(option.CMDRef)
			if cmdRefDir != "" {
				genMarkdown(cmd, cmdRefDir)
				os.Exit(0)
			}

			// Open socket for using gops to get stacktraces of the agent.
			addr := fmt.Sprintf("127.0.0.1:%d", viper.GetInt(option.GopsPort))
			addrField := logrus.Fields{"address": addr}
			if err := gops.Listen(gops.Options{
				Addr:                   addr,
				ReuseSocketAddrAndPort: true,
			}); err != nil {
				log.WithError(err).WithFields(addrField).Fatal("Cannot start gops server")
			}
			log.WithFields(addrField).Info("Started gops server")

			initEnv()
			runOperator()
		},
	}

	// Deprecated: remove in 1.9
	apiServerPort  uint16
	shutdownSignal = make(chan struct{})

	ciliumK8sClient clientset.Interface

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

func initEnv() {
	// Prepopulate option.Config with options from CLI.
	option.Config.Populate()
	operatorOption.Config.Populate()

	// add hooks after setting up metrics in the option.Confog
	logging.DefaultLogger.Hooks.Add(metrics.NewLoggingHook(components.CiliumOperatortName))

	// Logging should always be bootstrapped first. Do not add any code above this!
	logging.SetupLogging(option.Config.LogDriver, logging.LogOptions(option.Config.LogOpt), binaryName, option.Config.Debug)

	option.LogRegisteredOptions(log)
	// Enable fallback to direct API probing to check for support of Leases in
	// case Discovery API fails.
	option.Config.EnableK8sLeasesFallbackDiscovery()
}

func initK8s(k8sInitDone chan struct{}) {
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
}

func doCleanup(exitCode int) {
	isLeader.Store(false)
	gops.Close()
	close(shutdownSignal)
	leaderElectionCtxCancel()
	os.Exit(exitCode)
}

func main() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGINT, unix.SIGTERM)

	go func() {
		<-signals
		doCleanup(0)
	}()

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
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

// runOperator implements the logic of leader election for cilium-operator using
// built-in leader election capbility in kubernetes.
// See: https://github.com/kubernetes/client-go/blob/master/examples/leader-election/main.go
func runOperator() {
	log.Infof("Cilium Operator %s", version.Version)
	k8sInitDone := make(chan struct{})
	isLeader.Store(false)
	go startServer(shutdownSignal, k8sInitDone, getAPIServerAddr()...)

	if operatorOption.Config.EnableMetrics {
		operatorMetrics.Register()
	}

	initK8s(k8sInitDone)

	capabilities := k8sversion.Capabilities()
	if !capabilities.MinimalVersionMet {
		log.Fatalf("Minimal kubernetes version not met: %s < %s",
			k8sversion.Version(), k8sversion.MinimalVersionConstraint)
	}

	// Register the CRDs after validating that we are running on a supported
	// version of K8s.
	if err := k8s.RegisterCRDs(); err != nil {
		log.WithError(err).Fatal("Unable to register CRDs")
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
	operatorID = rand.RandomStringWithPrefix(operatorID+"-", 10)

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

		LeaseDuration: operatorOption.Config.LeaderElectionLeaseDuration,
		RenewDeadline: operatorOption.Config.LeaderElectionRenewDeadline,
		RetryPeriod:   operatorOption.Config.LeaderElectionRetryPeriod,

		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: onOperatorStartLeading,
			OnStoppedLeading: func() {
				log.WithField("operator-id", operatorID).Info("Leader election lost")
				// Cleanup everything here, and exit.
				doCleanup(1)
			},
			OnNewLeader: func(identity string) {
				if identity == operatorID {
					log.Info("Leading the operator HA deployment")
				} else {
					log.WithFields(logrus.Fields{
						"newLeader":  identity,
						"operatorID": operatorID,
					}).Info("Leader re-election complete")
				}
			},
		},
	})
}

// onOperatorStartLeading is the function called once the operator starts leading
// in HA mode.
func onOperatorStartLeading(ctx context.Context) {
	isLeader.Store(true)

	ciliumK8sClient = k8s.CiliumClient()

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

	log.WithField(logfields.Mode, option.Config.IPAM).Info("Initializing IPAM")

	switch ipamMode := option.Config.IPAM; ipamMode {
	case ipamOption.IPAMAzure, ipamOption.IPAMENI, ipamOption.IPAMClusterPool:
		alloc, providerBuiltin := allocatorProviders[ipamMode]
		if !providerBuiltin {
			log.Fatalf("%s allocator is not supported by this version of %s", ipamMode, binaryName)
		}

		if err := alloc.Init(ctx); err != nil {
			log.WithError(err).Fatalf("Unable to init %s allocator", ipamMode)
		}

		nm, err := alloc.Start(&ciliumNodeUpdateImplementation{})
		if err != nil {
			log.WithError(err).Fatalf("Unable to start %s allocator", ipamMode)
		}

		startSynchronizingCiliumNodes(nm)
		nodeManager = &nm

		switch ipamMode {
		case ipamOption.IPAMClusterPool:
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
	default:
		startSynchronizingCiliumNodes(NOPNodeManager)
		nodeManager = &NOPNodeManager
	}

	if kvstoreEnabled() {
		if operatorOption.Config.SyncK8sServices {
			operatorWatchers.StartSynchronizingServices(true)
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
					scopedLog.Infof("%s running with service synchronization: automatic etcd service translation enabled", binaryName)

					svcGetter := k8s.ServiceIPGetter(&operatorWatchers.K8sSvcCache)

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
							svcGetter = operatorWatchers.NewServiceGetter(&sc)
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
			scopedLog.Infof("%s running without service synchronization: automatic etcd service translation disabled", binaryName)
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

	if operatorOption.Config.IdentityGCInterval != 0 {
		identityRateLimiter = rate.NewLimiter(
			operatorOption.Config.IdentityGCRateInterval,
			operatorOption.Config.IdentityGCRateLimit,
		)
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

	if operatorOption.Config.EndpointGCInterval != 0 {
		enableCiliumEndpointSyncGC(false)
	} else {
		// Even if the EndpointGC is disabled we still want it to run at least
		// once. This is to prevent leftover CEPs from populating ipcache with
		// stale entries.
		enableCiliumEndpointSyncGC(true)
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
