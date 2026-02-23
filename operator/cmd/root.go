// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/shell"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/util/workqueue"

	operatorApi "github.com/cilium/cilium/api/v1/operator/server"
	"github.com/cilium/cilium/cilium-dbg/cmd/troubleshoot"
	"github.com/cilium/cilium/operator/api"
	"github.com/cilium/cilium/operator/auth"
	"github.com/cilium/cilium/operator/doublewrite"
	"github.com/cilium/cilium/operator/endpointgc"
	"github.com/cilium/cilium/operator/endpointslicegc"
	"github.com/cilium/cilium/operator/identitygc"
	operatorK8s "github.com/cilium/cilium/operator/k8s"
	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/pkg/bgp"
	"github.com/cilium/cilium/operator/pkg/ciliumendpointslice"
	"github.com/cilium/cilium/operator/pkg/ciliumenvoyconfig"
	"github.com/cilium/cilium/operator/pkg/ciliumidentity"
	"github.com/cilium/cilium/operator/pkg/client"
	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	gatewayapi "github.com/cilium/cilium/operator/pkg/gateway-api"
	"github.com/cilium/cilium/operator/pkg/ingress"
	"github.com/cilium/cilium/operator/pkg/ipam"
	"github.com/cilium/cilium/operator/pkg/kvstore/locksweeper"
	"github.com/cilium/cilium/operator/pkg/kvstore/nodesgc"
	"github.com/cilium/cilium/operator/pkg/lbipam"
	"github.com/cilium/cilium/operator/pkg/networkpolicy"
	"github.com/cilium/cilium/operator/pkg/nodeipam"
	"github.com/cilium/cilium/operator/pkg/secretsync"
	"github.com/cilium/cilium/operator/pkg/ztunnel"
	"github.com/cilium/cilium/operator/policyderivative"
	"github.com/cilium/cilium/operator/unmanagedpods"
	operatorWatchers "github.com/cilium/cilium/operator/watchers"
	clustercfgcell "github.com/cilium/cilium/pkg/clustermesh/clustercfg/cell"
	"github.com/cilium/cilium/pkg/clustermesh/endpointslicesync"
	"github.com/cilium/cilium/pkg/clustermesh/mcsapi"
	cmnamespace "github.com/cilium/cilium/pkg/clustermesh/namespace"
	cmoperator "github.com/cilium/cilium/pkg/clustermesh/operator"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/cmdref"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/heartbeat"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	features "github.com/cilium/cilium/pkg/metrics/features/operator"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/version"
	wgAgent "github.com/cilium/cilium/pkg/wireguard/agent"
)

var (
	InfrastructureCells = []cell.Cell{
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

		// Provide the logic to map DNS names matching Kubernetes services to the
		// corresponding ClusterIP, without depending on CoreDNS. Leveraged by etcd
		// and clustermesh. We provide ServiceResource here as it is a dependency
		// of the ServiceResolverCell.
		cell.Provide(k8s.ServiceResource),
		dial.ResourceServiceResolverCell,

		// Provides the Client to access the KVStore.
		cell.Provide(kvstoreExtraOptions),
		kvstore.Cell(kvstore.DisabledBackendName),

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
		shell.ServerCell(defaults.ShellSockPath),
	}

	ControlPlaneCells = []cell.Cell{
		cell.Config(cmtypes.DefaultClusterInfo),
		cell.Config(cmtypes.DefaultPolicyConfig),
		cell.Invoke(cmtypes.ClusterInfo.InitClusterIDMax),
		cell.Invoke(cmtypes.ClusterInfo.Validate),

		cell.Provide(func() *option.DaemonConfig {
			return option.Config
		}),

		cell.Provide(func() *operatorOption.OperatorConfig {
			return operatorOption.Config
		}),

		ipsec.OperatorCell,
		wgAgent.OperatorCell,

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
			operatorCfg *operatorOption.OperatorConfig,
			daemonCfg *option.DaemonConfig,
			clientset k8sClient.Clientset,
		) unmanagedpods.SharedConfig {
			return unmanagedpods.SharedConfig{
				DisableCiliumEndpointCRD: daemonCfg.DisableCiliumEndpointCRD,
				K8sEnabled:               clientset.IsEnabled(),
			}
		}),

		cell.Provide(func(
			daemonCfg *option.DaemonConfig,
			clientset k8sClient.Clientset,
		) policyderivative.SharedConfig {
			return policyderivative.SharedConfig{
				EnableCiliumNetworkPolicy:            daemonCfg.EnableCiliumNetworkPolicy,
				EnableCiliumClusterwideNetworkPolicy: daemonCfg.EnableCiliumClusterwideNetworkPolicy,
				ClusterName:                          daemonCfg.ClusterName,
				K8sEnabled:                           clientset.IsEnabled(),
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
			isLeader.Load,
		),
		api.MetricsHandlerCell,
		controller.Cell,
		operatorApi.SpecCell,
		api.ServerCell,
	}

	// These cells are started only after the operator is elected leader.
	ControlPlaneLeaderCells = []cell.Cell{
		// The CRDs registration should be the first operation to be invoked after the operator is elected leader.
		apis.RegisterCRDsCell,
		operatorK8s.ResourcesCell,

		// Updates the heartbeat key in the kvstore.
		heartbeat.Enabled,
		heartbeat.Cell,

		// Configures the cluster config key in the kvstore.
		clustercfgcell.WithSyncedCanaries(false),
		clustercfgcell.Cell,

		bgp.Cell,
		lbipam.Cell,
		nodeipam.Cell,
		auth.Cell,
		store.Cell,
		cmoperator.Cell,
		endpointslicesync.Cell,
		mcsapi.Cell,
		locksweeper.Cell,
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

		// Unmanaged Pods controller restarts pods that don't have a corresponding
		// CiliumEndpoint object. This is primarily used to restart kube-dns pods
		// that may have started before Cilium was ready.
		unmanagedpods.Cell,

		// Policy Derivative Watchers manage derivative policies for CNP and CCNP
		// resources. They watch for policy CRD events and update policy-to-groups
		// mappings periodically.
		policyderivative.Cell,

		// Cilium Endpoint Slice Garbage Collector. One-off GC that deletes all CES
		// present in a cluster when CES feature is disabled.
		endpointslicegc.Cell,

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

		// Provide the namespace manager for service and serviceexport synchronizers.
		cmnamespace.Cell,

		// Synchronizes K8s services to KVStore.
		cell.Provide(func(cfg *operatorOption.OperatorConfig, dcfg *option.DaemonConfig) operatorWatchers.ServiceSyncConfig {
			return operatorWatchers.ServiceSyncConfig{
				Enabled: cfg.SyncK8sServices,
			}
		}),
		operatorWatchers.ServiceSyncCell,

		// Synchronizes K8s ServiceExports to KVStore
		mcsapi.ServiceExportSyncCell,

		// Cilium L7 LoadBalancing with Envoy.
		ciliumenvoyconfig.Cell,

		// Informational policy validation.
		networkpolicy.Cell,

		// Synchronizes Secrets referenced in CiliumNetworkPolicy to the configured secret
		// namespace.
		networkpolicy.SecretSyncCell,

		// The feature Cell will retrieve information from all other cells /
		// configuration to describe, in form of prometheus metrics, which
		// features are enabled on the operator.
		features.Cell,

		// GC of stale node entries in the KVStore
		nodesgc.Cell,

		// Provides the ztunnel daemonset controller if ztunnel encryption
		// is specified.
		ztunnel.Cell,
	}

	binaryName = filepath.Base(os.Args[0])

	leaderElectionResourceLockName = "cilium-operator-resource-lock"

	// Use a Go context so we can tell the leaderelection code when we
	// want to step down
	leaderElectionCtx       context.Context
	leaderElectionCtxCancel context.CancelFunc

	// isLeader is an atomic boolean value that is true when the Operator is
	// elected leader. Otherwise, it is false.
	isLeader atomic.Bool
)

// Operator returns the cell.Module needed to build the Cilium operator hive.
// Instead of a plain global variable the module is built by this function so that
// the init functions in the ipam package can run first and add the proper
// allocator provider (clusterpool, multipool, aws and so on) before generating the
// IPAM cell.
func Operator() cell.Cell {
	var (
		Infrastructure = cell.Module(
			"operator-infra",
			"Operator Infrastructure",

			InfrastructureCells...,
		)

		// ControlPlane implements the control functions.
		ControlPlane = cell.Module(
			"operator-controlplane",
			"Operator Control Plane",

			append(
				ControlPlaneCells,
				WithLeaderLifecycle(
					append(
						ControlPlaneLeaderCells,
						ipam.Cell(),
					)...,
				),
			)...,
		)
	)

	return cell.Module(
		"operator",
		"Cilium Operator",

		Infrastructure,
		ControlPlane,

		// This needs to be the last in the list, so that the start hook responsible
		// for the operator leader election is guaranteed to be executed last, when
		// all the previous ones have already completed. Otherwise, cells within
		// the "WithLeaderLifecycle" scope may be incorrectly started too early,
		// given that "registerOperatorHooks" does not depend on all of their
		// individual dependencies outside of that scope.
		cell.Invoke(
			registerOperatorHooks,
		),
	)
}

func NewOperatorCmd(h *hive.Hive) *cobra.Command {
	cmd := &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
		Run: func(cobraCmd *cobra.Command, args []string) {
			// slogloggercheck: the logger has been initialized in the cobra.OnInitialize
			logger := logging.DefaultSlogLogger.With(logfields.LogSubsys, binaryName)

			initEnv(logger, h.Viper())

			// Pass the DefaultSlogLogger to the hive after being initialized
			// with the initEnv which sets up the logging.DefaultSlogLogger with
			// the user-options.
			// slogloggercheck: the logger has been initialized in the cobra.OnInitialize
			if err := h.Run(logging.DefaultSlogLogger); err != nil {
				// slogloggercheck: log fatal errors using the default logger before it's initialized.
				logging.Fatal(logging.DefaultSlogLogger, err.Error())
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
		hive.CiliumShellCmd,
		h.Command(),
	)

	// slogloggercheck: using default logger for configuration initialization
	InitGlobalFlags(logging.DefaultSlogLogger, cmd, h.Viper())

	// slogloggercheck: using default logger for configuration initialization
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
	option.Config.PopulateEnableCiliumNodeCRD(logger, vp)

	// Populate the operator config with the options from Viper
	operatorOption.Config.Populate(logger, vp)

	// add hooks after setting up metrics in the option.Config
	logging.AddHandlers(metrics.NewLoggingHook())

	// Register the user options in the logs
	option.LogRegisteredSlogOptions(vp, logger)

	// Create the run directory. Used at least by the shell.sock.
	os.MkdirAll(defaults.RuntimePath, defaults.RuntimePathRights)

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
				// It's imperative that we stop immediately here. Concurrent execution threads
				// acting on shared state in k8s/kvstore do so under the assumption that this
				// operator leads the deployment, which is no longer true once we hit this callback.
				// If we linger longer than the grace period between the RenewDeadline and the
				// LeaseDuration, we end up with two operators acting as leaders.
				logging.Fatal(log, "Leader election lost, shutting down.", logfields.OperatorID, operatorID)
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

var legacyCell = cell.Module(
	"legacy-cell",
	"Cilium operator legacy cell",

	cell.Invoke(registerLegacyOnLeader),
)

type params struct {
	cell.In
	Lifecycle                cell.Lifecycle
	Clientset                k8sClient.Clientset
	Resources                operatorK8s.Resources
	SvcResolver              dial.Resolver
	CfgClusterMeshPolicy     cmtypes.PolicyConfig
	MetricsRegistry          *metrics.Registry
	Logger                   *slog.Logger
	WorkQueueMetricsProvider workqueue.MetricsProvider
}

func registerLegacyOnLeader(p params) {
	ctx, cancel := context.WithCancel(context.Background())
	legacy := &legacyOnLeader{
		ctx:                      ctx,
		cancel:                   cancel,
		clientset:                p.Clientset,
		resources:                p.Resources,
		cfgClusterMeshPolicy:     p.CfgClusterMeshPolicy,
		workqueueMetricsProvider: p.WorkQueueMetricsProvider,
		metricsRegistry:          p.MetricsRegistry,
		logger:                   p.Logger,
	}
	p.Lifecycle.Append(cell.Hook{
		OnStart: legacy.onStart,
		OnStop:  legacy.onStop,
	})
}

type legacyOnLeader struct {
	ctx                      context.Context
	cancel                   context.CancelFunc
	clientset                k8sClient.Clientset
	wg                       sync.WaitGroup
	resources                operatorK8s.Resources
	cfgClusterMeshPolicy     cmtypes.PolicyConfig
	metricsRegistry          *metrics.Registry
	workqueueMetricsProvider workqueue.MetricsProvider
	logger                   *slog.Logger
}

func (legacy *legacyOnLeader) onStop(_ cell.HookContext) error {
	legacy.cancel()

	// Wait for background goroutines to finish.
	legacy.wg.Wait()

	return nil
}

// onStart is the function called once the operator starts leading
// in HA mode.
func (legacy *legacyOnLeader) onStart(ctx cell.HookContext) error {
	isLeader.Store(true)

	watcherLogger := legacy.logger.With(logfields.LogSubsys, "watchers")

	if legacy.clientset.IsEnabled() &&
		(operatorOption.Config.RemoveCiliumNodeTaints || operatorOption.Config.SetCiliumIsUpCondition) {
		legacy.logger.InfoContext(ctx,
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

	if legacy.clientset.IsEnabled() {
		if operatorOption.Config.NodesGCInterval != 0 {
			operatorWatchers.RunCiliumNodeGC(legacy.ctx, &legacy.wg, legacy.clientset, legacy.resources.CiliumNodes,
				operatorOption.Config.NodesGCInterval, watcherLogger, legacy.workqueueMetricsProvider)
		}
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

	if legacy.clientset.IsEnabled() {
		if err := labelsfilter.ParseLabelPrefixCfg(legacy.logger, option.Config.Labels, option.Config.NodeLabels, option.Config.LabelPrefixFile); err != nil {
			logging.Fatal(legacy.logger, "Unable to parse Label prefix configuration", logfields.Error, err)
		}
	}

	legacy.logger.InfoContext(ctx, "Initialization complete")
	return nil
}

// kvstoreExtraOptions provides the extra options to initialize the kvstore client.
func kvstoreExtraOptions(in struct {
	cell.In

	Logger *slog.Logger

	ClientSet k8sClient.Clientset
	Resolver  dial.Resolver
},
) kvstore.ExtraOptions {
	var goopts kvstore.ExtraOptions

	// If K8s is enabled we can do the service translation automagically by
	// looking at services from k8s and retrieve the service IP from that.
	// This makes cilium to not depend on kube dns to interact with etcd
	if in.ClientSet.IsEnabled() {
		goopts.DialOption = []grpc.DialOption{
			grpc.WithContextDialer(dial.NewContextDialer(in.Logger, in.Resolver)),
		}
	}

	return goopts
}
