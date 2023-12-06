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
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	operatorApi "github.com/cilium/cilium/api/v1/operator/server"
	"github.com/cilium/cilium/operator/api"
	"github.com/cilium/cilium/operator/auth"
	"github.com/cilium/cilium/operator/endpointgc"
	"github.com/cilium/cilium/operator/identitygc"
	operatorK8s "github.com/cilium/cilium/operator/k8s"
	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/pkg/ciliumendpointslice"
	"github.com/cilium/cilium/operator/pkg/ciliumenvoyconfig"
	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	gatewayapi "github.com/cilium/cilium/operator/pkg/gateway-api"
	"github.com/cilium/cilium/operator/pkg/ingress"
	"github.com/cilium/cilium/operator/pkg/lbipam"
	"github.com/cilium/cilium/operator/pkg/secretsync"
	operatorWatchers "github.com/cilium/cilium/operator/watchers"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/controller"
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
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/version"
)

var (
	Operator = cell.Module(
		"operator",
		"Cilium Operator",

		Infrastructure,
		ControlPlane,
	)

	Infrastructure = cell.Module(
		"operator-infra",
		"Operator Infrastructure",

		// Register the pprof HTTP handlers, to get runtime profiling data.
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

		// Runs the gops agent, a tool to diagnose Go processes.
		gops.Cell(defaults.GopsPortOperator),

		// Provides Clientset, API for accessing Kubernetes objects.
		k8sClient.Cell,

		// Provides the modular metrics registry, metric HTTP server and legacy metrics cell.
		operatorMetrics.Cell,
		cell.Provide(func(
			operatorCfg *operatorOption.OperatorConfig,
		) operatorMetrics.SharedConfig {
			return operatorMetrics.SharedConfig{
				// Cloud provider specific allocators needs to read operatorCfg.EnableMetrics
				// to add their metrics when it's set to true. Therefore, we leave the flag as global
				// instead of declaring it as part of the metrics cell.
				// This should be changed once the IPAM allocator is modularized.
				EnableMetrics:    operatorCfg.EnableMetrics,
				EnableGatewayAPI: operatorCfg.EnableGatewayAPI,
			}
		}),
	)

	// ControlPlane implements the control functions.
	ControlPlane = cell.Module(
		"operator-controlplane",
		"Operator Control Plane",

		cell.Config(cmtypes.DefaultClusterInfo),
		cell.Invoke(func(cinfo cmtypes.ClusterInfo) error { return cinfo.InitClusterIDMax() }),
		cell.Invoke(func(cinfo cmtypes.ClusterInfo) error { return cinfo.Validate() }),

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
				K8sNamespace:           daemonCfg.CiliumNamespaceName(),
			}
		}),

		cell.Provide(func(
			daemonCfg *option.DaemonConfig,
		) ciliumendpointslice.SharedConfig {
			return ciliumendpointslice.SharedConfig{
				EnableCiliumEndpointSlice: daemonCfg.EnableCiliumEndpointSlice,
			}
		}),

		cell.Provide(func(
			operatorCfg *operatorOption.OperatorConfig,
			daemonCfg *option.DaemonConfig,
		) endpointgc.SharedConfig {
			return endpointgc.SharedConfig{
				Interval:                 operatorCfg.EndpointGCInterval,
				DisableCiliumEndpointCRD: daemonCfg.DisableCiliumEndpointCRD,
			}
		}),

		api.HealthHandlerCell(
			kvstoreEnabled,
			isLeader.Load,
		),
		api.MetricsHandlerCell,
		controller.Cell,
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
			store.Cell,
			legacyCell,

			// When running in kvstore mode, the start hook of the identity GC
			// cell blocks until the kvstore client has been initialized, which
			// is performed by the legacyCell start hook. Hence, the identity GC
			// cell is registered afterwards, to ensure the ordering of the
			// setup operations. This is a hacky workaround until the kvstore is
			// refactored into a proper cell.
			identitygc.Cell,

			// CiliumEndpointSlice controller depends on the CiliumEndpoint and
			// CiliumEndpointSlice resources. It reconciles the state of CESs in the
			// cluster based on the CEPs and CESs events.
			// It is disabled if CiliumEndpointSlice is disabled in the cluster -
			// when --enable-cilium-endpoint-slice is false.
			ciliumendpointslice.Cell,

			// Cilium Endpoint Garbage Collector. It removes all leaked Cilium
			// Endpoints. Either once or periodically it validates all the present
			// Cilium Endpoints and delete the ones that should be deleted.
			endpointgc.Cell,

			// Integrates the controller-runtime library and provides its components via Hive.
			controllerruntime.Cell,

			// Cilium Gateway API controller that manages the Gateway API related CRDs.
			gatewayapi.Cell,

			// Cilium Ingress controller that manages the Kubernetes Ingress related CRDs.
			ingress.Cell,

			// Cilium Secret synchronizes K8s TLS Secrets referenced by
			// Ciliums "Ingress resources" from the application namespaces into a dedicated
			// secrets namespace that is accessible by the Cilium Agents.
			// Resources might be K8s `Ingress` or Gateway API `Gateway`.
			secretsync.Cell,

			// Cilium L7 LoadBalancing with Envoy.
			ciliumenvoyconfig.Cell,
		),
	)

	binaryName = filepath.Base(os.Args[0])

	log = logging.DefaultLogger.WithField(logfields.LogSubsys, binaryName)

	FlagsHooks []ProviderFlagsHooks

	leaderElectionResourceLockName = "cilium-operator-resource-lock"

	// Use a Go context so we can tell the leaderelection code when we
	// want to step down
	leaderElectionCtx       context.Context
	leaderElectionCtxCancel context.CancelFunc

	// isLeader is an atomic boolean value that is true when the Operator is
	// elected leader. Otherwise, it is false.
	isLeader atomic.Bool
)

func NewOperatorCmd(h *hive.Hive) *cobra.Command {
	cmd := &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
		Run: func(cobraCmd *cobra.Command, args []string) {
			cmdRefDir := h.Viper().GetString(option.CMDRef)
			if cmdRefDir != "" {
				genMarkdown(cobraCmd, cmdRefDir)
				os.Exit(0)
			}

			initEnv(h.Viper())

			if err := h.Run(); err != nil {
				log.Fatal(err)
			}
		},
	}

	h.RegisterFlags(cmd.Flags())

	// Enable fallback to direct API probing to check for support of Leases in
	// case Discovery API fails.
	h.Viper().Set(option.K8sEnableAPIDiscovery, true)

	// Overwrite the metrics namespace with the one specific for the Operator
	metrics.Namespace = metrics.CiliumOperatorNamespace

	cmd.AddCommand(
		MetricsCmd,
		h.Command(),
	)

	InitGlobalFlags(cmd, h.Viper())
	for _, hook := range FlagsHooks {
		hook.RegisterProviderFlag(cmd, h.Viper())
	}

	cobra.OnInitialize(option.InitConfig(cmd, "Cilium-Operator", "cilium-operators", h.Viper()))

	return cmd
}

func Execute(cmd *cobra.Command) {
	if err := cmd.Execute(); err != nil {
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

func initEnv(vp *viper.Viper) {
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
// built-in leader election capability in kubernetes.
// See: https://github.com/kubernetes/client-go/blob/master/examples/leader-election/main.go
func runOperator(lc *LeaderLifecycle, clientset k8sClient.Clientset, shutdowner hive.Shutdowner) {
	isLeader.Store(false)

	leaderElectionCtx, leaderElectionCtxCancel = context.WithCancel(context.Background())

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
	operatorID = fmt.Sprintf("%s-%s", operatorID, rand.String(10))

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

func registerLegacyOnLeader(lc hive.Lifecycle, clientset k8sClient.Clientset, resources operatorK8s.Resources, factory store.Factory) {
	ctx, cancel := context.WithCancel(context.Background())
	legacy := &legacyOnLeader{
		ctx:          ctx,
		cancel:       cancel,
		clientset:    clientset,
		resources:    resources,
		storeFactory: factory,
	}
	lc.Append(hive.Hook{
		OnStart: legacy.onStart,
		OnStop:  legacy.onStop,
	})
}

type legacyOnLeader struct {
	ctx          context.Context
	cancel       context.CancelFunc
	clientset    k8sClient.Clientset
	wg           sync.WaitGroup
	resources    operatorK8s.Resources
	storeFactory store.Factory
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
		ipamOption.IPAMMultiPool,
		ipamOption.IPAMAlibabaCloud:
		alloc, providerBuiltin := allocatorProviders[ipamMode]
		if !providerBuiltin {
			log.Fatalf("%s allocator is not supported by this version of %s", ipamMode, binaryName)
		}

		if err := alloc.Init(legacy.ctx); err != nil {
			log.WithError(err).Fatalf("Unable to init %s allocator", ipamMode)
		}

		if pooledAlloc, ok := alloc.(operatorWatchers.PooledAllocatorProvider); ok {
			// The following operation will block until all pools are restored, thus it
			// is safe to continue starting node allocation right after return.
			operatorWatchers.StartIPPoolAllocator(legacy.ctx, legacy.clientset, pooledAlloc, legacy.resources.CiliumPodIPPools)
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
			clusterInfo := cmtypes.ClusterInfo{
				ID:   option.Config.ClusterID,
				Name: option.Config.ClusterName,
			}
			operatorWatchers.StartSynchronizingServices(legacy.ctx, &legacy.wg, operatorWatchers.ServiceSyncParameters{
				ClusterInfo:  clusterInfo,
				Clientset:    legacy.clientset,
				Services:     legacy.resources.Services,
				Endpoints:    legacy.resources.Endpoints,
				SharedOnly:   true,
				StoreFactory: legacy.storeFactory,
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
							slimSvcObj, err := k8s.TransformToK8sService(k8sSvc)
							if err != nil {
								scopedLog.WithFields(logrus.Fields{
									logfields.ServiceName:      k8sSvc.Name,
									logfields.ServiceNamespace: k8sSvc.Namespace,
								}).Error("Failed to transform k8s service")
							} else {
								slimSvc := k8s.CastInformerEvent[slim_corev1.Service](slimSvcObj)
								if slimSvc == nil {
									// This will never happen but still log it
									scopedLog.WithFields(logrus.Fields{
										logfields.ServiceName:      k8sSvc.Name,
										logfields.ServiceNamespace: k8sSvc.Namespace,
									}).Warn("BUG: invalid k8s service")
								}
								sc.UpdateService(slimSvc, nil)
								svcGetter = operatorWatchers.NewServiceGetter(sc)
							}
						case k8sErrors.IsNotFound(err):
							scopedLog.Error("Service not found in k8s")
						default:
							scopedLog.Warning("Unable to get service spec from k8s, this might cause network disruptions with etcd")
						}
					}

					log := log.WithField(logfields.LogSubsys, "etcd")
					goopts = &kvstore.ExtraOptions{
						DialOption: []grpc.DialOption{
							grpc.WithContextDialer(k8s.CreateCustomDialer(svcGetter, log, true)),
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

		if operatorOption.Config.NodesGCInterval != 0 {
			operatorWatchers.RunCiliumNodeGC(legacy.ctx, &legacy.wg, legacy.clientset, ciliumNodeSynchronizer.ciliumNodeStore, operatorOption.Config.NodesGCInterval)
		}
	}

	if option.Config.IPAM == ipamOption.IPAMClusterPool || option.Config.IPAM == ipamOption.IPAMMultiPool {
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

	log.Info("Initialization complete")
	return nil
}
