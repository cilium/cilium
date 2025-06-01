// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	operatorApi "github.com/cilium/cilium/api/v1/operator/server"
	"github.com/cilium/cilium/cilium-dbg/cmd/troubleshoot"
	"github.com/cilium/cilium/operator/api"
	"github.com/cilium/cilium/operator/auth"
	"github.com/cilium/cilium/operator/doublewrite"
	"github.com/cilium/cilium/operator/endpointgc"
	"github.com/cilium/cilium/operator/identitygc"
	operatorK8s "github.com/cilium/cilium/operator/k8s"
	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/pkg/bgpv2"
	"github.com/cilium/cilium/operator/pkg/ciliumendpointslice"
	"github.com/cilium/cilium/operator/pkg/ciliumenvoyconfig"
	"github.com/cilium/cilium/operator/pkg/ciliumidentity"
	"github.com/cilium/cilium/operator/pkg/client"
	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	gatewayapi "github.com/cilium/cilium/operator/pkg/gateway-api"
	"github.com/cilium/cilium/operator/pkg/ingress"
	"github.com/cilium/cilium/operator/pkg/lbipam"
	"github.com/cilium/cilium/operator/pkg/networkpolicy"
	"github.com/cilium/cilium/operator/pkg/nodeipam"
	"github.com/cilium/cilium/operator/pkg/secretsync"
	operatorWatchers "github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/clustermesh/endpointslicesync"
	"github.com/cilium/cilium/pkg/clustermesh/mcsapi"
	cmoperator "github.com/cilium/cilium/pkg/clustermesh/operator"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/cmdref"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/apis"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	features "github.com/cilium/cilium/pkg/metrics/features/operator"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pprof"
	shellclient "github.com/cilium/cilium/pkg/shell/client"
	shell "github.com/cilium/cilium/pkg/shell/server"
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
		cell.ProvidePrivate(func(cfg operatorPprofConfig) pprof.Config {
			return cfg.Config()
		}),
		pprof.Cell(defaultOperatorPprofConfig),

		// Runs the gops agent, a tool to diagnose Go processes.
		gops.Cell(defaults.EnableGops, defaults.GopsPortOperator),

		// Provides a Kubernetes client and ClientBuilderFunc that can be used by other cells to create a client.
		client.Cell,
		cell.ProvidePrivate(func(clientParams operatorClientParams) k8sClient.ClientParams {
			return k8sClient.ClientParams{
				K8sClientQPS:   clientParams.OperatorK8sClientQPS,
				K8sClientBurst: clientParams.OperatorK8sClientBurst,
			}
		}),
		cell.Config(operatorClientParams{
			OperatorK8sClientQPS:   100.0,
			OperatorK8sClientBurst: 200,
		}),

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
				EnableMetrics: operatorCfg.EnableMetrics,
			}
		}),

		// Shell for inspecting the operator. Listens on the 'shell.sock' UNIX socket.
		shell.Cell,
	)

	// ControlPlane implements the control functions.
	ControlPlane = cell.Module(
		"operator-controlplane",
		"Operator Control Plane",

		cell.Config(cmtypes.DefaultClusterInfo),
		cell.Config(cmtypes.DefaultPolicyConfig),
		cell.Invoke(cmtypes.ClusterInfo.InitClusterIDMax),
		cell.Invoke(cmtypes.ClusterInfo.Validate),

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

		cell.Provide(func(
			daemonCfg *option.DaemonConfig,
		) ciliumidentity.SharedConfig {
			return ciliumidentity.SharedConfig{
				EnableCiliumEndpointSlice: daemonCfg.EnableCiliumEndpointSlice,
				DisableNetworkPolicy:      !option.NetworkPolicyEnabled(daemonCfg),
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

		// These cells are started only after the operator is elected leader.
		WithLeaderLifecycle(
			// The CRDs registration should be the first operation to be invoked after the operator is elected leader.
			apis.RegisterCRDsCell,
			operatorK8s.ResourcesCell,

			bgpv2.Cell,
			lbipam.Cell,
			nodeipam.Cell,
			auth.Cell,
			store.Cell,
			cmoperator.Cell,
			endpointslicesync.Cell,
			mcsapi.Cell,
			legacyCell,

			// When running in kvstore mode, the start hook of the identity GC
			// cell blocks until the kvstore client has been initialized, which
			// is performed by the legacyCell start hook. Hence, the identity GC
			// cell is registered afterwards, to ensure the ordering of the
			// setup operations. This is a hacky workaround until the kvstore is
			// refactored into a proper cell.
			identitygc.Cell,

			// CiliumIdentity controller manages Cilium Identity API objects. It
			// creates and updates Cilium Identities (CIDs) based on CID,
			// Pod, Namespace and CES events.
			ciliumidentity.Cell,

			// When the Double Write Identity Allocation mode is enabled, the Double Write
			// Metric Reporter helps with monitoring the state of identities in KVStore and CRD
			doublewrite.Cell,

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

			// Informational policy validation.
			networkpolicy.Cell,

			// Synchronizes Secrets referenced in CiliumNetworkPolicy to the configured secret
			// namespace.
			networkpolicy.SecretSyncCell,

			// Provide the logic to map DNS names matching Kubernetes services to the
			// corresponding ClusterIP, without depending on CoreDNS. Leveraged by etcd
			// and clustermesh.
			dial.ServiceResolverCell,

			// The feature Cell will retrieve information from all other cells /
			// configuration to describe, in form of prometheus metrics, which
			// features are enabled on the operator.
			features.Cell,
		),
	)

	binaryName = filepath.Base(os.Args[0])

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
			logger := logging.DefaultSlogLogger.With(logfields.LogSubsys, binaryName)

			initEnv(logger, h.Viper())

			if err := h.Run(logger); err != nil {
				logging.Fatal(logger, err.Error())
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
		cmdref.NewCmd(cmd),
		MetricsCmd,
		StatusCmd,
		troubleshoot.Cmd,
		shellclient.ShellCmd,
		h.Command(),
	)

	InitGlobalFlags(logging.DefaultSlogLogger, cmd, h.Viper())
	for _, hook := range FlagsHooks {
		hook.RegisterProviderFlag(cmd, h.Viper())
	}

	cobra.OnInitialize(option.InitConfig(logging.DefaultSlogLogger, cmd, "Cilium-Operator", "cilium-operators", h.Viper()))

	return cmd
}

func Execute(cmd *cobra.Command) {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func registerOperatorHooks(log *slog.Logger, lc cell.Lifecycle, llc *LeaderLifecycle, clientset k8sClient.Clientset, shutdowner hive.Shutdowner) {
	var wg sync.WaitGroup
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			wg.Add(1)
			go func() {
				runOperator(log, llc, clientset, shutdowner)
				wg.Done()
			}()
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			if err := llc.Stop(log, ctx); err != nil {
				return err
			}
			doCleanup()
			wg.Wait()
			return nil
		},
	})
}

func initEnv(logger *slog.Logger, vp *viper.Viper) {
	// Setup logging with the options directly from Viper. There's no dependency
	// from this function with the rest of the DaemonConfig.
	option.Config.SetupLogging(vp, binaryName)
	// Populate the global config with the options from Viper
	option.Config.Populate(logger, vp)

	// Populate the operator config with the options from Viper
	operatorOption.Config.Populate(logger, vp)

	// add hooks after setting up metrics in the option.Config
	logging.AddHooks(metrics.NewLoggingHook())

	// Register the user options in the logs
	option.LogRegisteredSlogOptions(vp, logger)
	logger.Info("Cilium Operator", logfields.Version, version.Version)
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
func runOperator(log *slog.Logger, lc *LeaderLifecycle, clientset k8sClient.Clientset, shutdowner hive.Shutdowner) {
	isLeader.Store(false)

	leaderElectionCtx, leaderElectionCtxCancel = context.WithCancel(context.Background())

	if clientset.IsEnabled() {
		capabilities := k8sversion.Capabilities()
		if !capabilities.MinimalVersionMet {
			logging.Fatal(log, fmt.Sprintf("Minimal kubernetes version not met: %s < %s",
				k8sversion.Version(), k8sversion.MinimalVersionConstraint))
		}
	}

	// We only support Operator in HA mode for Kubernetes Versions having support for
	// LeasesResourceLock.
	// See docs on capabilities.LeasesResourceLock for more context.
	if !k8sversion.Capabilities().LeasesResourceLock {
		log.Info("Support for coordination.k8s.io/v1 not present, fallback to non HA mode")

		if err := lc.Start(log, leaderElectionCtx); err != nil {
			logging.Fatal(log, "Failed to start leading", logfields.Error, err)
		}
		return
	}

	// Get hostname for identity name of the lease lock holder.
	// We identify the leader of the operator cluster using hostname.
	operatorID, err := os.Hostname()
	if err != nil {
		logging.Fatal(log, "Failed to get hostname when generating lease lock identity", logfields.Error, err)
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
		logging.Fatal(log, "Failed to create resource lock for leader election", logfields.Error, err)
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
				if err := lc.Start(log, ctx); err != nil {
					log.Error("Failed to start when elected leader, shutting down", logfields.Error, err)
					shutdowner.Shutdown(hive.ShutdownWithError(err))
				}
			},
			OnStoppedLeading: func() {
				log.Info("Leader election lost", logfields.OperatorID, operatorID)
				// Cleanup everything here, and exit.
				shutdowner.Shutdown(hive.ShutdownWithError(errors.New("Leader election lost")))
			},
			OnNewLeader: func(identity string) {
				if identity == operatorID {
					log.Info("Leading the operator HA deployment")
				} else {
					log.Info(
						"Leader re-election complete",
						logfields.NewLeader, operatorID,
						logfields.OperatorID, operatorID,
					)
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
		option.Config.IdentityAllocationMode == option.IdentityAllocationModeDoubleWriteReadCRD ||
		option.Config.IdentityAllocationMode == option.IdentityAllocationModeDoubleWriteReadKVstore ||
		operatorOption.Config.SyncK8sServices ||
		operatorOption.Config.SyncK8sNodes
}

var legacyCell = cell.Module(
	"legacy-cell",
	"Cilium operator legacy cell",

	cell.Invoke(registerLegacyOnLeader),

	// Provides the unamanged pods metric
	metrics.Metric(NewUnmanagedPodsMetric),
)

func registerLegacyOnLeader(lc cell.Lifecycle, clientset k8sClient.Clientset, resources operatorK8s.Resources, factory store.Factory, svcResolver *dial.ServiceResolver, cfgMCSAPI cmoperator.MCSAPIConfig, cfgClusterMeshPolicy cmtypes.PolicyConfig, metrics *UnmanagedPodsMetric, logger *slog.Logger) {
	ctx, cancel := context.WithCancel(context.Background())
	legacy := &legacyOnLeader{
		ctx:                  ctx,
		cancel:               cancel,
		clientset:            clientset,
		resources:            resources,
		storeFactory:         factory,
		svcResolver:          svcResolver,
		cfgMCSAPI:            cfgMCSAPI,
		cfgClusterMeshPolicy: cfgClusterMeshPolicy,
		metrics:              metrics,
		logger:               logger,
	}
	lc.Append(cell.Hook{
		OnStart: legacy.onStart,
		OnStop:  legacy.onStop,
	})
}

type legacyOnLeader struct {
	ctx                  context.Context
	cancel               context.CancelFunc
	clientset            k8sClient.Clientset
	wg                   sync.WaitGroup
	resources            operatorK8s.Resources
	storeFactory         store.Factory
	svcResolver          *dial.ServiceResolver
	cfgMCSAPI            cmoperator.MCSAPIConfig
	cfgClusterMeshPolicy cmtypes.PolicyConfig
	metrics              *UnmanagedPodsMetric

	logger *slog.Logger
}

func (legacy *legacyOnLeader) onStop(_ cell.HookContext) error {
	legacy.cancel()

	// Wait for background goroutines to finish.
	legacy.wg.Wait()

	return nil
}

// OnOperatorStartLeading is the function called once the operator starts leading
// in HA mode.
func (legacy *legacyOnLeader) onStart(_ cell.HookContext) error {
	isLeader.Store(true)

	// Restart kube-dns as soon as possible to parallelize re-initialization
	// of DNS with other operation functions.
	// If kube-dns is not managed by Cilium it can prevent
	// etcd from reaching out kube-dns in EKS.
	// If this logic is modified, make sure the operator's clusterrole logic for
	// pods/delete is also up-to-date.
	if !legacy.clientset.IsEnabled() {
		legacy.logger.Info("KubeDNS unmanaged pods controller disabled due to kubernetes support not enabled")
	} else if option.Config.DisableCiliumEndpointCRD {
		legacy.logger.Info(fmt.Sprintf("KubeDNS unmanaged pods controller disabled as %q option is set to 'disabled' in Cilium ConfigMap", option.DisableCiliumEndpointCRDName))
	} else if operatorOption.Config.UnmanagedPodWatcherInterval != 0 {
		legacy.wg.Add(1)
		go func() {
			defer legacy.wg.Done()
			enableUnmanagedController(legacy.ctx, legacy.logger, &legacy.wg, legacy.clientset, legacy.metrics)
		}()
	}

	var (
		nodeManager allocator.NodeEventHandler
		withKVStore bool
	)

	legacy.logger.Info(
		"Initializing IPAM",
		logfields.Mode, option.Config.IPAM,
	)
	watcherLogger := legacy.logger.With(logfields.LogSubsys, "watchers")

	switch ipamMode := option.Config.IPAM; ipamMode {
	case ipamOption.IPAMAzure,
		ipamOption.IPAMENI,
		ipamOption.IPAMClusterPool,
		ipamOption.IPAMMultiPool,
		ipamOption.IPAMAlibabaCloud:
		alloc, providerBuiltin := allocatorProviders[ipamMode]
		if !providerBuiltin {
			logging.Fatal(legacy.logger, fmt.Sprintf("%s allocator is not supported by this version of %s", ipamMode, binaryName))
		}

		if err := alloc.Init(legacy.ctx, legacy.logger); err != nil {
			logging.Fatal(legacy.logger, fmt.Sprintf("Unable to init %s allocator", ipamMode), logfields.Error, err)
		}

		if pooledAlloc, ok := alloc.(operatorWatchers.PooledAllocatorProvider); ok {
			// The following operation will block until all pools are restored, thus it
			// is safe to continue starting node allocation right after return.
			operatorWatchers.StartIPPoolAllocator(legacy.ctx, legacy.clientset, pooledAlloc, legacy.resources.CiliumPodIPPools,
				watcherLogger)
		}

		nm, err := alloc.Start(legacy.ctx, &ciliumNodeUpdateImplementation{legacy.clientset})
		if err != nil {
			logging.Fatal(legacy.logger, fmt.Sprintf("Unable to start %s allocator", ipamMode), logfields.Error, err)
		}

		nodeManager = nm
	}

	if kvstoreEnabled() {
		var goopts *kvstore.ExtraOptions
		scoppedLogger := legacy.logger.With(
			logfields.KVStore, option.Config.KVStore,
			logfields.Address, option.Config.KVStoreOpt[fmt.Sprintf("%s.address", option.Config.KVStore)],
		)

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
				StoreFactory: legacy.storeFactory,
				SyncCallback: func(_ context.Context) {},
			}, legacy.logger)
			legacy.wg.Add(1)
			go func() {
				mcsapi.StartSynchronizingServiceExports(legacy.ctx, mcsapi.ServiceExportSyncParameters{
					Logger:                  legacy.logger,
					ClusterName:             clusterInfo.Name,
					ClusterMeshEnableMCSAPI: legacy.cfgMCSAPI.ClusterMeshEnableMCSAPI,
					Clientset:               legacy.clientset,
					ServiceExports:          legacy.resources.ServiceExports,
					Services:                legacy.resources.Services,
					StoreFactory:            legacy.storeFactory,
					SyncCallback:            func(context.Context) {},
				})
				legacy.wg.Done()
			}()
		}

		if legacy.clientset.IsEnabled() {
			// If K8s is enabled we can do the service translation automagically by
			// looking at services from k8s and retrieve the service IP from that.
			// This makes cilium to not depend on kube dns to interact with etcd
			etcdLog := scoppedLogger.With(logfields.LogSubsys, "etcd")
			goopts = &kvstore.ExtraOptions{
				DialOption: []grpc.DialOption{
					grpc.WithContextDialer(dial.NewContextDialer(etcdLog, legacy.svcResolver)),
				},
			}
		}

		scoppedLogger.Info("Connecting to kvstore")
		if err := kvstore.Setup(legacy.ctx, scoppedLogger, option.Config.KVStore, option.Config.KVStoreOpt, goopts); err != nil {
			logging.Fatal(scoppedLogger, "Unable to setup kvstore", logfields.Error, err)
		}

		if legacy.clientset.IsEnabled() && operatorOption.Config.SyncK8sNodes {
			withKVStore = true
		}

		startKvstoreWatchdog(scoppedLogger, legacy.cfgMCSAPI)
	}

	if legacy.clientset.IsEnabled() &&
		(operatorOption.Config.RemoveCiliumNodeTaints || operatorOption.Config.SetCiliumIsUpCondition) {
		legacy.logger.Info(
			"Managing Cilium Node Taints or Setting Cilium Is Up Condition for Kubernetes Nodes",
			logfields.K8sNamespace, operatorOption.Config.CiliumK8sNamespace,
			logfields.LabelSelectorFlagOption, operatorOption.Config.CiliumPodLabels,
			logfields.RemoveCiliumNodeTaintsFlagOption, operatorOption.Config.RemoveCiliumNodeTaints,
			logfields.SetCiliumNodeTaintsFlagOption, operatorOption.Config.SetCiliumNodeTaints,
			logfields.SetCiliumIsUpConditionFlagOption, operatorOption.Config.SetCiliumIsUpCondition,
		)

		operatorWatchers.HandleNodeTolerationAndTaints(&legacy.wg, legacy.clientset, legacy.ctx.Done(),
			watcherLogger)
	}

	ciliumNodeSynchronizer := newCiliumNodeSynchronizer(legacy.logger, legacy.clientset, nodeManager, withKVStore)

	if legacy.clientset.IsEnabled() {
		// ciliumNodeSynchronizer uses operatorWatchers.PodStore for IPAM surge
		// allocation. Initializing PodStore from Pod resource is temporary until
		// ciliumNodeSynchronizer is migrated to a cell.
		podStore, err := legacy.resources.Pods.Store(legacy.ctx)
		if err != nil {
			logging.Fatal(legacy.logger, "Unable to retrieve Pod store from Pod resource watcher", logfields.Error, err)
		}
		operatorWatchers.PodStore = podStore.CacheStore()

		if err := ciliumNodeSynchronizer.Start(legacy.ctx, &legacy.wg, podStore); err != nil {
			logging.Fatal(legacy.logger, "Unable to setup cilium node synchronizer", logfields.Error, err)
		}

		if operatorOption.Config.NodesGCInterval != 0 {
			operatorWatchers.RunCiliumNodeGC(legacy.ctx, &legacy.wg, legacy.clientset, ciliumNodeSynchronizer.ciliumNodeStore,
				operatorOption.Config.NodesGCInterval, watcherLogger)
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

	if option.Config.IdentityAllocationMode == option.IdentityAllocationModeCRD ||
		option.Config.IdentityAllocationMode == option.IdentityAllocationModeDoubleWriteReadKVstore ||
		option.Config.IdentityAllocationMode == option.IdentityAllocationModeDoubleWriteReadCRD {
		if !legacy.clientset.IsEnabled() {
			logging.Fatal(legacy.logger, fmt.Sprintf("%s Identity allocation mode requires k8s to be configured.", option.Config.IdentityAllocationMode))
		}
		if operatorOption.Config.EndpointGCInterval == 0 {
			logging.Fatal(legacy.logger, "Cilium Identity garbage collector requires the CiliumEndpoint garbage collector to be enabled")
		}
	}

	clusterNamePolicy := cmtypes.LocalClusterNameForPolicies(legacy.cfgClusterMeshPolicy, option.Config.ClusterName)

	if legacy.clientset.IsEnabled() && option.Config.EnableCiliumNetworkPolicy {
		enableCNPWatcher(legacy.ctx, legacy.logger, &legacy.wg, legacy.clientset, clusterNamePolicy)
	}

	if legacy.clientset.IsEnabled() && option.Config.EnableCiliumClusterwideNetworkPolicy {
		enableCCNPWatcher(legacy.ctx, legacy.logger, &legacy.wg, legacy.clientset, clusterNamePolicy)
	}

	if legacy.clientset.IsEnabled() {
		if err := labelsfilter.ParseLabelPrefixCfg(legacy.logger, option.Config.Labels, option.Config.NodeLabels, option.Config.LabelPrefixFile); err != nil {
			logging.Fatal(legacy.logger, "Unable to parse Label prefix configuration", logfields.Error, err)
		}
	}

	legacy.logger.Info("Initialization complete")
	return nil
}
