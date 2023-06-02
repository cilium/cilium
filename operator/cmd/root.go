// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	xrate "golang.org/x/time/rate"
	"google.golang.org/grpc"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	operatorApi "github.com/cilium/cilium/api/v1/operator/server"
	"github.com/cilium/cilium/operator/api"
	"github.com/cilium/cilium/operator/auth"
	"github.com/cilium/cilium/operator/identitygc"
	operatorK8s "github.com/cilium/cilium/operator/k8s"
	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	ces "github.com/cilium/cilium/operator/pkg/ciliumendpointslice"
	gatewayapi "github.com/cilium/cilium/operator/pkg/gateway-api"
	"github.com/cilium/cilium/operator/pkg/ingress"
	"github.com/cilium/cilium/operator/pkg/lbipam"
	operatorWatchers "github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/rand"
	"github.com/cilium/cilium/pkg/version"
)

var (
	binaryName = filepath.Base(os.Args[0])

	log = logging.DefaultLogger.WithField(logfields.LogSubsys, binaryName)

	rootCmd = &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
	}

	leaderElectionResourceLockName = "cilium-operator-resource-lock"

	// Use a Go context so we can tell the leaderelection code when we
	// want to step down
	leaderElectionCtx       context.Context
	leaderElectionCtxCancel context.CancelFunc

	operatorAddr string

	// isLeader is an atomic boolean value that is true when the Operator is
	// elected leader. Otherwise, it is false.
	isLeader atomic.Bool

	// OperatorCell are the operator specific cells without infrastructure cells.
	// Used also in tests.
	OperatorCell = cell.Module(
		"operator",
		"Cilium Operator",

		cell.Invoke(
			registerOperatorHooks,
		),

		cell.Provide(func() *option.DaemonConfig {
			return option.Config
		}),

		cell.Provide(func() *operatorOption.OperatorConfig {
			return operatorOption.Config
		}),

		cell.Provide(func(
			daemonCfg *option.DaemonConfig,
			operatorCfg *operatorOption.OperatorConfig,
		) identitygc.SharedConfig {
			return identitygc.SharedConfig{
				IdentityAllocationMode: daemonCfg.IdentityAllocationMode,
				EnableMetrics:          operatorCfg.EnableMetrics,
				ClusterName:            daemonCfg.LocalClusterName(),
				K8sNamespace:           daemonCfg.CiliumNamespaceName(),
				ClusterID:              daemonCfg.LocalClusterID(),
			}
		}),

		api.HealthHandlerCell(
			kvstoreEnabled,
			isLeader.Load,
		),
		api.MetricsHandlerCell,
		operatorApi.SpecCell,
		api.ServerCell,

		// Provides a global job registry which cells can use to spawn job groups.
		job.Cell,

		// These cells are started only after the operator is elected leader.
		WithLeaderLifecycle(
			// The CRDs registration should be the first operation to be invoked after the operator is elected leader.
			apis.RegisterCRDsCell,
			operatorK8s.ResourcesCell,

			lbipam.Cell,
			auth.Cell,
			legacyCell,

			// When running in kvstore mode, the start hook of the identity GC
			// cell blocks until the kvstore client has been initialized, which
			// is performed by the legacyCell start hook. Hence, the identity GC
			// cell is registered afterwards, to ensure the ordering of the
			// setup operations. This is a hacky workaround until the kvstore is
			// refactored into a proper cell.
			identitygc.Cell,
		),
	)

	operatorHive *hive.Hive = newOperatorHive()

	Vp *viper.Viper = operatorHive.Viper()
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func registerOperatorHooks(lc hive.Lifecycle, llc *LeaderLifecycle, clientset k8sClient.Clientset, shutdowner hive.Shutdowner) {
	var wg sync.WaitGroup
	lc.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			wg.Add(1)
			go func() {
				runOperator(llc, clientset, shutdowner)
				wg.Done()
			}()
			return nil
		},
		OnStop: func(ctx hive.HookContext) error {
			if err := llc.Stop(ctx); err != nil {
				return err
			}
			doCleanup()
			wg.Wait()
			return nil
		},
	})
}

func newOperatorHive() *hive.Hive {
	h := hive.New(
		pprof.Cell,
		cell.ProvidePrivate(func(cfg operatorPprofConfig) pprof.Config {
			return pprof.Config{
				Pprof:        cfg.OperatorPprof,
				PprofAddress: cfg.OperatorPprofAddress,
				PprofPort:    cfg.OperatorPprofPort,
			}
		}),
		cell.Config(operatorPprofConfig{
			OperatorPprofAddress: operatorOption.PprofAddressOperator,
			OperatorPprofPort:    operatorOption.PprofPortOperator,
		}),

		gops.Cell(defaults.GopsPortOperator),
		k8sClient.Cell,
		OperatorCell,
	)
	h.RegisterFlags(rootCmd.Flags())

	// Enable fallback to direct API probing to check for support of Leases in
	// case Discovery API fails.
	h.Viper().Set(option.K8sEnableAPIDiscovery, true)

	return h
}

func init() {
	rootCmd.AddCommand(MetricsCmd)
	rootCmd.AddCommand(operatorHive.Command())

	rootCmd.Run = func(cobraCmd *cobra.Command, args []string) {
		cmdRefDir := operatorHive.Viper().GetString(option.CMDRef)
		if cmdRefDir != "" {
			genMarkdown(cobraCmd, cmdRefDir)
			os.Exit(0)
		}

		initEnv()

		if err := operatorHive.Run(); err != nil {
			log.Fatal(err)
		}
	}
}

func initEnv() {
	vp := operatorHive.Viper()
	// Prepopulate option.Config with options from CLI.
	option.Config.Populate(vp)
	operatorOption.Config.Populate(vp)

	// add hooks after setting up metrics in the option.Confog
	logging.DefaultLogger.Hooks.Add(metrics.NewLoggingHook(components.CiliumOperatortName))

	// Logging should always be bootstrapped first. Do not add any code above this!
	if err := logging.SetupLogging(option.Config.LogDriver, logging.LogOptions(option.Config.LogOpt), binaryName, option.Config.Debug); err != nil {
		log.Fatal(err)
	}

	option.LogRegisteredOptions(vp, log)
	log.Infof("Cilium Operator %s", version.Version)
}

func doCleanup() {
	isLeader.Store(false)

	// Cancelling this context here makes sure that if the operator hold the
	// leader lease, it will be released.
	leaderElectionCtxCancel()
}

// runOperator implements the logic of leader election for cilium-operator using
// built-in leader election capbility in kubernetes.
// See: https://github.com/kubernetes/client-go/blob/master/examples/leader-election/main.go
func runOperator(lc *LeaderLifecycle, clientset k8sClient.Clientset, shutdowner hive.Shutdowner) {
	isLeader.Store(false)

	leaderElectionCtx, leaderElectionCtxCancel = context.WithCancel(context.Background())

	if operatorOption.Config.EnableMetrics {
		operatorMetrics.Register()
	}

	if clientset.IsEnabled() {
		capabilities := k8sversion.Capabilities()
		if !capabilities.MinimalVersionMet {
			log.Fatalf("Minimal kubernetes version not met: %s < %s",
				k8sversion.Version(), k8sversion.MinimalVersionConstraint)
		}
	}

	// We only support Operator in HA mode for Kubernetes Versions having support for
	// LeasesResourceLock.
	// See docs on capabilities.LeasesResourceLock for more context.
	if !k8sversion.Capabilities().LeasesResourceLock {
		log.Info("Support for coordination.k8s.io/v1 not present, fallback to non HA mode")

		if err := lc.Start(leaderElectionCtx); err != nil {
			log.WithError(err).Fatal("Failed to start leading")
		}
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

	leResourceLock, err := resourcelock.NewFromKubeconfig(
		resourcelock.LeasesResourceLock,
		ns,
		leaderElectionResourceLockName,
		resourcelock.ResourceLockConfig{
			// Identity name of the lock holder
			Identity: operatorID,
		},
		clientset.RestConfig(),
		operatorOption.Config.LeaderElectionRenewDeadline)
	if err != nil {
		log.WithError(err).Fatal("Failed to create resource lock for leader election")
	}

	// Start the leader election for running cilium-operators
	log.Info("Waiting for leader election")
	leaderelection.RunOrDie(leaderElectionCtx, leaderelection.LeaderElectionConfig{
		Name: leaderElectionResourceLockName,

		Lock:            leResourceLock,
		ReleaseOnCancel: true,

		LeaseDuration: operatorOption.Config.LeaderElectionLeaseDuration,
		RenewDeadline: operatorOption.Config.LeaderElectionRenewDeadline,
		RetryPeriod:   operatorOption.Config.LeaderElectionRetryPeriod,

		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				if err := lc.Start(ctx); err != nil {
					log.WithError(err).Error("Failed to start when elected leader, shutting down")
					shutdowner.Shutdown(hive.ShutdownWithError(err))
				}
			},
			OnStoppedLeading: func() {
				log.WithField("operator-id", operatorID).Info("Leader election lost")
				// Cleanup everything here, and exit.
				shutdowner.Shutdown(hive.ShutdownWithError(errors.New("Leader election lost")))
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

func kvstoreEnabled() bool {
	if option.Config.KVStore == "" {
		return false
	}

	return option.Config.IdentityAllocationMode == option.IdentityAllocationModeKVstore ||
		operatorOption.Config.SyncK8sServices ||
		operatorOption.Config.SyncK8sNodes
}

var legacyCell = cell.Invoke(registerLegacyOnLeader)

func registerLegacyOnLeader(lc hive.Lifecycle, clientset k8sClient.Clientset, resources operatorK8s.Resources) {
	ctx, cancel := context.WithCancel(context.Background())
	legacy := &legacyOnLeader{
		ctx:       ctx,
		cancel:    cancel,
		clientset: clientset,
		resources: resources,
	}
	lc.Append(hive.Hook{
		OnStart: legacy.onStart,
		OnStop:  legacy.onStop,
	})
}

type legacyOnLeader struct {
	ctx       context.Context
	cancel    context.CancelFunc
	clientset k8sClient.Clientset
	wg        sync.WaitGroup
	resources operatorK8s.Resources
}

func (legacy *legacyOnLeader) onStop(_ hive.HookContext) error {
	legacy.cancel()

	// Wait for background goroutines to finish.
	legacy.wg.Wait()

	return nil
}

// OnOperatorStartLeading is the function called once the operator starts leading
// in HA mode.
func (legacy *legacyOnLeader) onStart(_ hive.HookContext) error {
	isLeader.Store(true)

	// If CiliumEndpointSlice feature is enabled, create CESController, start CEP watcher and run controller.
	if legacy.clientset.IsEnabled() && !option.Config.DisableCiliumEndpointCRD && option.Config.EnableCiliumEndpointSlice {
		log.Info("Create and run CES controller, start CEP watcher")
		// Initialize  the CES controller
		cesController := ces.NewCESController(
			legacy.ctx,
			&legacy.wg,
			legacy.clientset,
			operatorOption.Config.CESMaxCEPsInCES,
			operatorOption.Config.CESSlicingMode,
			float64(legacy.clientset.Config().K8sClientQPS),
			legacy.clientset.Config().K8sClientBurst)
		// Start CEP watcher
		operatorWatchers.CiliumEndpointsSliceInit(legacy.ctx, &legacy.wg, legacy.clientset, cesController)
		// Start the CES controller, after current CEPs are synced locally in cache.
		legacy.wg.Add(1)
		go func() {
			defer legacy.wg.Done()
			cesController.Run(operatorWatchers.CiliumEndpointStore, legacy.ctx.Done())
		}()
	}

	// Restart kube-dns as soon as possible since it helps etcd-operator to be
	// properly setup. If kube-dns is not managed by Cilium it can prevent
	// etcd from reaching out kube-dns in EKS.
	// If this logic is modified, make sure the operator's clusterrole logic for
	// pods/delete is also up-to-date.
	if !legacy.clientset.IsEnabled() {
		log.Infof("KubeDNS unmanaged pods controller disabled due to kubernetes support not enabled")
	} else if option.Config.DisableCiliumEndpointCRD {
		log.Infof("KubeDNS unmanaged pods controller disabled as %q option is set to 'disabled' in Cilium ConfigMap", option.DisableCiliumEndpointCRDName)
	} else if operatorOption.Config.UnmanagedPodWatcherInterval != 0 {
		legacy.wg.Add(1)
		go func() {
			defer legacy.wg.Done()
			enableUnmanagedController(legacy.ctx, &legacy.wg, legacy.clientset)
		}()
	}

	var (
		nodeManager allocator.NodeEventHandler
		err         error
		withKVStore bool
	)

	log.WithField(logfields.Mode, option.Config.IPAM).Info("Initializing IPAM")

	switch ipamMode := option.Config.IPAM; ipamMode {
	case ipamOption.IPAMAzure,
		ipamOption.IPAMENI,
		ipamOption.IPAMClusterPool,
		ipamOption.IPAMClusterPoolV2,
		ipamOption.IPAMMultiPool,
		ipamOption.IPAMAlibabaCloud:
		alloc, providerBuiltin := allocatorProviders[ipamMode]
		if !providerBuiltin {
			log.Fatalf("%s allocator is not supported by this version of %s", ipamMode, binaryName)
		}

		if err := alloc.Init(legacy.ctx); err != nil {
			log.WithError(err).Fatalf("Unable to init %s allocator", ipamMode)
		}

		nm, err := alloc.Start(legacy.ctx, &ciliumNodeUpdateImplementation{legacy.clientset})
		if err != nil {
			log.WithError(err).Fatalf("Unable to start %s allocator", ipamMode)
		}

		nodeManager = nm
	}

	if operatorOption.Config.BGPAnnounceLBIP {
		log.Info("Starting LB IP allocator")
		operatorWatchers.StartBGPBetaLBIPAllocator(legacy.ctx, legacy.clientset, legacy.resources.Services)
	}

	if kvstoreEnabled() {
		var goopts *kvstore.ExtraOptions
		scopedLog := log.WithFields(logrus.Fields{
			"kvstore": option.Config.KVStore,
			"address": option.Config.KVStoreOpt[fmt.Sprintf("%s.address", option.Config.KVStore)],
		})

		if legacy.clientset.IsEnabled() && operatorOption.Config.SyncK8sServices {
			operatorWatchers.StartSynchronizingServices(legacy.ctx, &legacy.wg, operatorWatchers.ServiceSyncParameters{
				ServiceSyncConfiguration: option.Config,

				Clientset:  legacy.clientset,
				Services:   legacy.resources.Services,
				SharedOnly: true,
			})
			// If K8s is enabled we can do the service translation automagically by
			// looking at services from k8s and retrieve the service IP from that.
			// This makes cilium to not depend on kube dns to interact with etcd
			if legacy.clientset.IsEnabled() {
				svcURL, isETCDOperator := kvstore.IsEtcdOperator(option.Config.KVStore, option.Config.KVStoreOpt, option.Config.K8sNamespace)
				if isETCDOperator {
					scopedLog.Infof("%s running with service synchronization: automatic etcd service translation enabled", binaryName)

					svcGetter := k8s.ServiceIPGetter(operatorWatchers.K8sSvcCache)

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
						k8sSvc, err := legacy.clientset.CoreV1().Services(namespace).Get(legacy.ctx, name, metav1.GetOptions{})
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
							svcGetter = operatorWatchers.NewServiceGetter(sc)
						case k8sErrors.IsNotFound(err):
							scopedLog.Error("Service not found in k8s")
						default:
							scopedLog.Warning("Unable to get service spec from k8s, this might cause network disruptions with etcd")
						}
					}

					log := log.WithField(logfields.LogSubsys, "etcd")
					goopts = &kvstore.ExtraOptions{
						DialOption: []grpc.DialOption{
							grpc.WithContextDialer(k8s.CreateCustomDialer(svcGetter, log)),
						},
					}
				}
			}
		} else {
			scopedLog.Infof("%s running without service synchronization: automatic etcd service translation disabled", binaryName)
		}
		scopedLog.Info("Connecting to kvstore")
		if err := kvstore.Setup(legacy.ctx, option.Config.KVStore, option.Config.KVStoreOpt, goopts); err != nil {
			scopedLog.WithError(err).Fatal("Unable to setup kvstore")
		}

		if legacy.clientset.IsEnabled() && operatorOption.Config.SyncK8sNodes {
			withKVStore = true
		}

		startKvstoreWatchdog()
	}

	if legacy.clientset.IsEnabled() &&
		(operatorOption.Config.RemoveCiliumNodeTaints || operatorOption.Config.SetCiliumIsUpCondition) {
		log.WithFields(logrus.Fields{
			logfields.K8sNamespace:       operatorOption.Config.CiliumK8sNamespace,
			"label-selector":             operatorOption.Config.CiliumPodLabels,
			"remove-cilium-node-taints":  operatorOption.Config.RemoveCiliumNodeTaints,
			"set-cilium-node-taints":     operatorOption.Config.SetCiliumNodeTaints,
			"set-cilium-is-up-condition": operatorOption.Config.SetCiliumIsUpCondition,
		}).Info("Managing Cilium Node Taints or Setting Cilium Is Up Condition for Kubernetes Nodes")

		operatorWatchers.HandleNodeTolerationAndTaints(&legacy.wg, legacy.clientset, legacy.ctx.Done())
	}

	ciliumNodeSynchronizer := newCiliumNodeSynchronizer(legacy.clientset, nodeManager, withKVStore)

	if legacy.clientset.IsEnabled() {
		if err := ciliumNodeSynchronizer.Start(legacy.ctx, &legacy.wg); err != nil {
			log.WithError(err).Fatal("Unable to setup cilium node synchronizer")
		}

		if operatorOption.Config.SkipCNPStatusStartupClean {
			log.Info("Skipping clean up of CNP and CCNP node status updates")
		} else {
			// If CNP status updates are disabled, we clean up all the
			// possible updates written when the option was enabled.
			// This is done to avoid accumulating stale updates and thus
			// hindering scalability for large clusters.
			RunCNPStatusNodesCleaner(
				legacy.ctx,
				legacy.clientset,
				xrate.NewLimiter(
					xrate.Limit(operatorOption.Config.CNPStatusCleanupQPS),
					operatorOption.Config.CNPStatusCleanupBurst,
				),
			)
		}

		if operatorOption.Config.CNPNodeStatusGCInterval != 0 {
			RunCNPNodeStatusGC(legacy.ctx, &legacy.wg, legacy.clientset, ciliumNodeSynchronizer.ciliumNodeStore)
		}

		if operatorOption.Config.NodesGCInterval != 0 {
			operatorWatchers.RunCiliumNodeGC(legacy.ctx, &legacy.wg, legacy.clientset, ciliumNodeSynchronizer.ciliumNodeStore, operatorOption.Config.NodesGCInterval)
		}
	}

	if option.Config.IPAM == ipamOption.IPAMClusterPool || option.Config.IPAM == ipamOption.IPAMClusterPoolV2 || option.Config.IPAM == ipamOption.IPAMMultiPool {
		// We will use CiliumNodes as the source of truth for the podCIDRs.
		// Once the CiliumNodes are synchronized with the operator we will
		// be able to watch for K8s Node events which they will be used
		// to create the remaining CiliumNodes.
		<-ciliumNodeSynchronizer.ciliumNodeManagerQueueSynced

		// We don't want CiliumNodes that don't have podCIDRs to be
		// allocated with a podCIDR already being used by another node.
		// For this reason we will call Resync after all CiliumNodes are
		// synced with the operator to signal the node manager, since it
		// knows all podCIDRs that are currently set in the cluster, that
		// it can allocate podCIDRs for the nodes that don't have a podCIDR
		// set.
		nodeManager.Resync(legacy.ctx, time.Time{})
	}

	if option.Config.IdentityAllocationMode == option.IdentityAllocationModeCRD {
		if !legacy.clientset.IsEnabled() {
			log.Fatal("CRD Identity allocation mode requires k8s to be configured.")
		}
		if operatorOption.Config.EndpointGCInterval == 0 {
			log.Fatal("Cilium Identity garbage collector requires the CiliumEndpoint garbage collector to be enabled")
		}
	}

	if legacy.clientset.IsEnabled() {
		if operatorOption.Config.EndpointGCInterval != 0 {
			enableCiliumEndpointSyncGC(legacy.ctx, &legacy.wg, legacy.clientset, ciliumNodeSynchronizer, false)
		} else {
			// Even if the EndpointGC is disabled we still want it to run at least
			// once. This is to prevent leftover CEPs from populating ipcache with
			// stale entries.
			enableCiliumEndpointSyncGC(legacy.ctx, &legacy.wg, legacy.clientset, ciliumNodeSynchronizer, true)
		}

		err = enableCNPWatcher(legacy.ctx, &legacy.wg, legacy.clientset)
		if err != nil {
			log.WithError(err).WithField(logfields.LogSubsys, "CNPWatcher").Fatal(
				"Cannot connect to Kubernetes apiserver ")
		}

		err = enableCCNPWatcher(legacy.ctx, &legacy.wg, legacy.clientset)
		if err != nil {
			log.WithError(err).WithField(logfields.LogSubsys, "CCNPWatcher").Fatal(
				"Cannot connect to Kubernetes apiserver ")
		}
	}

	if operatorOption.Config.EnableIngressController {
		ingressController, err := ingress.NewController(
			legacy.clientset,
			ingress.WithHTTPSEnforced(operatorOption.Config.EnforceIngressHTTPS),
			ingress.WithSecretsSyncEnabled(operatorOption.Config.EnableIngressSecretsSync),
			ingress.WithSecretsNamespace(operatorOption.Config.IngressSecretsNamespace),
			ingress.WithLBAnnotationPrefixes(operatorOption.Config.IngressLBAnnotationPrefixes),
			ingress.WithCiliumNamespace(operatorOption.Config.CiliumK8sNamespace),
			ingress.WithSharedLBServiceName(operatorOption.Config.IngressSharedLBServiceName),
			ingress.WithDefaultLoadbalancerMode(operatorOption.Config.IngressDefaultLoadbalancerMode),
			ingress.WithIdleTimeoutSeconds(operatorOption.Config.ProxyIdleTimeoutSeconds),
		)
		if err != nil {
			log.WithError(err).WithField(logfields.LogSubsys, ingress.Subsys).Fatal(
				"Failed to start ingress controller")
		}
		go ingressController.Run()
	}

	if operatorOption.Config.EnableGatewayAPI {
		gatewayController, err := gatewayapi.NewController(
			operatorOption.Config.EnableGatewayAPISecretsSync,
			operatorOption.Config.GatewayAPISecretsNamespace,
			operatorOption.Config.ProxyIdleTimeoutSeconds,
		)
		if err != nil {
			log.WithError(err).WithField(logfields.LogSubsys, gatewayapi.Subsys).Fatal(
				"Failed to create gateway controller")
		}
		go gatewayController.Run()
	}

	if operatorOption.Config.LoadBalancerL7 == "envoy" {
		log.Info("Starting Envoy load balancer controller")
		operatorWatchers.StartCECController(legacy.ctx, legacy.clientset, legacy.resources.Services,
			operatorOption.Config.LoadBalancerL7Ports,
			operatorOption.Config.LoadBalancerL7Algorithm,
			operatorOption.Config.ProxyIdleTimeoutSeconds,
		)
	}

	log.Info("Initialization complete")
	return nil
}
