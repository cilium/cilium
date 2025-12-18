// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/hive/shell"
	"github.com/cilium/statedb"
	"google.golang.org/grpc"

	healthApi "github.com/cilium/cilium/api/v1/health/server"
	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/daemon/healthz"
	"github.com/cilium/cilium/daemon/infraendpoints"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/daemon/restapi"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/auth"
	"github.com/cilium/cilium/pkg/bgp"
	cgroup "github.com/cilium/cilium/pkg/cgroups/manager"
	"github.com/cilium/cilium/pkg/ciliumenvoyconfig"
	"github.com/cilium/cilium/pkg/clustermesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/datapath"
	debugapi "github.com/cilium/cilium/pkg/debug/api"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/driftchecker"
	"github.com/cilium/cilium/pkg/dynamicconfig"
	"github.com/cilium/cilium/pkg/dynamiclifecycle"
	"github.com/cilium/cilium/pkg/egressgateway"
	endpoint "github.com/cilium/cilium/pkg/endpoint/cell"
	"github.com/cilium/cilium/pkg/envoy"
	fqdn "github.com/cilium/cilium/pkg/fqdn/cell"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/health"
	"github.com/cilium/cilium/pkg/healthconfig"
	hubble "github.com/cilium/cilium/pkg/hubble/cell"
	identity "github.com/cilium/cilium/pkg/identity/cell"
	ipamcell "github.com/cilium/cilium/pkg/ipam/cell"
	ipcache "github.com/cilium/cilium/pkg/ipcache/cell"
	ipmasq "github.com/cilium/cilium/pkg/ipmasq/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/hostfirewallbypass"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	kpr "github.com/cilium/cilium/pkg/kpr/initializer"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/l2announcer"
	"github.com/cilium/cilium/pkg/lbipamconfig"
	loadbalancer_cell "github.com/cilium/cilium/pkg/loadbalancer/cell"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maglev"
	ipmasqmaps "github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/maps/iptrace"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	natStats "github.com/cilium/cilium/pkg/maps/nat/stats"
	"github.com/cilium/cilium/pkg/maps/ratelimitmap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/features"
	"github.com/cilium/cilium/pkg/node"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/node/neighbordiscovery"
	nodesync "github.com/cilium/cilium/pkg/node/sync"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/nodeipamconfig"
	"github.com/cilium/cilium/pkg/option"
	policy "github.com/cilium/cilium/pkg/policy/cell"
	policyDirectory "github.com/cilium/cilium/pkg/policy/directory"
	policyK8s "github.com/cilium/cilium/pkg/policy/k8s"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/signal"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/status"
	"github.com/cilium/cilium/pkg/subnet"
	"github.com/cilium/cilium/pkg/svcrouteconfig"
	"github.com/cilium/cilium/pkg/ztunnel"
)

var (
	Agent = cell.Module(
		"agent",
		"Cilium Agent",

		Infrastructure,
		ControlPlane,
		datapath.Cell,
	)

	// Infrastructure provides access and services to the outside.
	// A cell should live here instead of ControlPlane if it is not needed by
	// integrations tests, or needs to be mocked.
	Infrastructure = cell.Module(
		"infra",
		"Infrastructure",

		// Register the pprof HTTP handlers, to get runtime profiling data.
		pprof.Cell(pprofConfig),

		// Runs the gops agent, a tool to diagnose Go processes.
		gops.Cell(defaults.EnableGops, defaults.GopsPortAgent),

		// Provides Clientset, API for accessing Kubernetes objects.
		k8sClient.Cell,

		// Provides optional configuration callback to bypass
		// host firewall when accessing Kubernetes objects.
		hostfirewallbypass.Cell,

		// Provide the logic to map DNS names matching Kubernetes services to the
		// corresponding ClusterIP, without depending on CoreDNS. Leveraged by etcd
		// and clustermesh. Note that it depends on k8s.ServiceResource, which is
		// currently provided as part of the ControlPlane module.
		dial.ServiceResolverCell,

		// Provides the Client to access the KVStore.
		cell.Provide(kvstoreExtraOptions),
		kvstore.Cell(kvstore.DisabledBackendName),
		cell.Invoke(kvstoreLocksGC),

		cni.Cell,

		// Provide the modular metrics registry, metric HTTP server and legacy metrics cell.
		metrics.AgentCell,

		// Provides cilium_datapath_drop/forward Prometheus metrics.
		metricsmap.Cell,

		// Provides the IP trace map.
		iptrace.Cell,

		// Provides cilium_bpf_ratelimit_dropped_total Prometheus metric.
		ratelimitmap.Cell,

		// Cilium API served over UNIX sockets. Accessed by the 'cilium' utility (not cilium-cli).
		server.Cell,
		cell.Invoke(configureAPIServer),

		// Store cell provides factory for creating watchStore/syncStore/storeManager
		// useful for synchronizing data from/to kvstore.
		store.Cell,

		// Provide CRD resource names for 'k8sSynced.CRDSyncCell' below.
		cell.Provide(func() k8sSynced.CRDSyncResourceNames { return k8sSynced.AgentCRDResourceNames() }),

		// CRDSyncCell provides a promise that is resolved as soon as CRDs used by the
		// agent have k8sSynced.
		// Allows cells to wait for CRDs before trying to list Cilium resources.
		// This is separate from k8sSynced.Cell as this one needs to be mocked for tests.
		k8sSynced.CRDSyncCell,

		// Shell for inspecting the agent. Listens on the 'shell.sock' UNIX socket.
		shell.ServerCell(defaults.ShellSockPath),

		// Cilium Agent Healthz endpoints (agent, kubeproxy, ...)
		healthz.Cell,
	)

	// ControlPlane implement the per-node control functions. These are pure
	// business logic and depend on datapath or infrastructure to perform
	// actions. This separation enables non-privileged integration testing of
	// the control-plane.
	ControlPlane = cell.Module(
		"controlplane",
		"Control Plane",

		// IP allocation and creation of agents infrastructure endpoints (host, health & ingress)
		infraendpoints.Cell,

		// Syncs local host entries to the lxc/endpoints BPF map and IPCache
		hostIPSyncCell,

		// Endpoint restoration at agent startup
		endpointRestoreCell,

		// LocalNodeStore holds onto the information about the local node and allows
		// observing changes to it.
		node.LocalNodeStoreCell,
		nodesync.LocalNodeSyncCell,

		// Controller provides flags and configuration related
		// to Controller management, concurrent control loops
		// which run throughout the system on specified intervals
		controller.Cell,

		// Shared resources provide access to k8s resources as event streams or as
		// read-only stores.
		agentK8s.ResourcesCell,

		// StateDB tables for Kubernetes objects.
		agentK8s.TablesCell,

		// Shared synchronization structures for waiting on K8s resources to
		// be synced
		k8sSynced.Cell,

		// Endpoint cell provides the Endpoint modules.
		endpoint.Cell,

		// NodeManager maintains a collection of other nodes in the cluster.
		nodeManager.Cell,

		// NodeNeighborDiscovery is a node handler that subscribes to the NodeManager
		// and ensures node IPs are "forwardable" by adding them to the forwardable IP table.
		// The neighbor subsystem will create neighbor entries for these forwardable IPs.
		neighbordiscovery.Cell,

		// Certificate manager provides an API for retrieving secrets and certificate in the form of TLS contexts.
		certificatemanager.Cell,

		// Cilium API specification cell makes the swagger model available for reuse
		server.SpecCell,

		// cilium-health connectivity probe API specification cell makes the swagger model available for reuse
		healthApi.SpecCell,

		// daemonCell wraps the legacy daemon initialization and provides Promise[*Daemon].
		daemonCell,

		// daemonConfigCell wraps legacy daemonconfig initialization and provides *option.DaemonConfig and Promise[*option.DaemonConfig]
		daemonConfigCell,

		// Maglev table computtations
		maglev.Cell,

		// LB-IPAM configuration
		lbipamconfig.Cell,

		// Node-IPAM configuration
		nodeipamconfig.Cell,

		// Control-plane for configuring service load-balancing
		loadbalancer_cell.Cell,

		// Proxy provides the proxy port allocation and related datapath coordination and
		// makes different L7 proxies (Envoy, DNS proxy) usable to Cilium endpoints through
		// a common Proxy 'redirect' abstraction.
		proxy.Cell,

		// Envoy cell which is the control-plane for the Envoy proxy.
		// It is used to provide support for Ingress, GatewayAPI and L7 network policies (e.g. HTTP).
		envoy.Cell,

		// CiliumEnvoyConfig provides support for the CRD CiliumEnvoyConfig that backs Ingress, Gateway API
		// and L7 loadbalancing.
		ciliumenvoyconfig.Cell,

		// Cilium REST API handlers
		restapi.Cell,

		// The BGP Control Plane which enables various BGP related interop.
		bgp.Cell,

		// Brokers datapath signals from signalmap
		signal.Cell,

		// Auth is responsible for authenticating a request if required by a policy.
		auth.Cell,

		// Provides Identity Controlplane (Responsible for allocating & managing security identities)
		identity.Cell,

		// IPCache cell provides IPCache (IP to identity mappings)
		ipcache.Cell,

		// IPAM provides IP address management.
		ipamcell.Cell,

		// Egress Gateway allows originating traffic from specific IPv4 addresses.
		egressgateway.Cell,

		// Provides the BPF ip-masq-agent maps
		ipmasqmaps.Cell,

		// Provides the BPF ip-masq-agent implementation, which is responsible for managing IP masquerading rules
		ipmasq.Cell,

		// Provides KPR config & initialization logic
		kpr.Cell,

		// Provides PolicyRepository (List of policy rules)
		policy.Cell,

		// K8s policy resource watcher cell. It depends on the half-initialized daemon which is
		// resolved by newDaemonPromise()
		policyK8s.Cell,

		// Directory policy watcher cell.
		policyDirectory.Cell,

		// ClusterMesh is the Cilium's multicluster implementation.
		cell.Config(cmtypes.DefaultClusterInfo),
		cell.Config(cmtypes.DefaultPolicyConfig),
		clustermesh.Cell,

		// L2announcer resolves l2announcement policies, services, node labels and devices into a list of IPs+netdevs
		// which need to be announced on the local network.
		l2announcer.Cell,

		// The node discovery cell provides the local node configuration and node discovery
		// which communicate changes in local node information to the API server or KVStore.
		nodediscovery.Cell,

		// Cgroup manager maintains Kubernetes and low-level metadata (cgroup path and
		// cgroup id) for local pods and their containers.
		cgroup.Cell,

		// NAT stats provides stat computation and tables for NAT map bpf maps.
		natStats.Cell,

		// Provide resource groups to watch.
		cell.Provide(func() watchers.ResourceGroupFunc { return allResourceGroups }),

		// K8s Watcher provides the core k8s watchers
		watchers.Cell,

		// Provides a wrapper of the cilium config that can be watched dynamically
		dynamicconfig.Cell,

		// Provides the manager for WithDynamicFeature()
		// Which allows to group the cell lifecycles together and control the enablement
		// by leveraging the dynamicconfig.Cell.
		dynamiclifecycle.Cell,

		// Allows agent to monitor the configuration drift and publish drift metric
		driftchecker.Cell,

		// Runs the Hubble servers and Hubble metrics.
		hubble.Cell,

		// The feature Cell will retrieve information from all other cells /
		// configuration to describe, in form of prometheus metrics, which
		// features are enabled on the agent.
		features.Cell,

		// Determines priorities of data sources.
		source.Cell,

		// FQDN rules cell provides the FQDN proxy functionality.
		fqdn.Cell,

		// Cilium health infrastructure (host and endpoint connectivity)
		health.Cell,

		// Cilium health config
		healthconfig.Cell,

		// Cilium Status Collector
		status.Cell,

		// Cilium Debuginfo API
		debugapi.Cell,

		svcrouteconfig.Cell,

		// Instantiates an xDS server used for zTunnel integration.
		ztunnel.Cell,

		// Subnet topology watcher and management.
		subnet.Cell,
	)
)

func configureAPIServer(cfg *option.DaemonConfig, s *server.Server, db *statedb.DB, swaggerSpec *server.Spec, logger *slog.Logger) {
	s.EnabledListeners = []string{"unix"}
	s.SocketPath = cfg.SocketPath
	s.ReadTimeout = apiTimeout
	s.WriteTimeout = apiTimeout

	const msg = "Required API option is disabled. This may prevent Cilium from operating correctly"
	hint := "Consider enabling this API in " + server.AdminEnableFlag
	for _, requiredAPI := range []string{
		"GetConfig",        // CNI: Used to detect detect IPAM mode
		"GetHealthz",       // Kubelet: daemon health checks
		"PutEndpointID",    // CNI: Provision the network for a new Pod
		"DeleteEndpointID", // CNI: Clean up networking for a deleted Pod
		"PostIPAM",         // CNI: Reserve IPs for new Pods
		"DeleteIPAMIP",     // CNI: Release IPs for deleted Pods
	} {
		if _, denied := swaggerSpec.DeniedAPIs[requiredAPI]; denied {
			logger.Warn(
				msg,
				logfields.Hint, hint,
				logfields.Params, requiredAPI,
			)
		}
	}
	api.DisableAPIs(logger, swaggerSpec.DeniedAPIs, s.GetAPI().AddMiddlewareFor)

	s.ConfigureAPI()

	// Add the /statedb HTTP handler
	mux := http.NewServeMux()
	mux.Handle("/", s.GetHandler())
	mux.Handle("/statedb/", http.StripPrefix("/statedb", db.HTTPHandler()))
	s.SetHandler(mux)
}

var pprofConfig = pprof.Config{
	Pprof:                     false,
	PprofAddress:              option.PprofAddressAgent,
	PprofPort:                 option.PprofPortAgent,
	PprofMutexProfileFraction: 0,
	PprofBlockProfileRate:     0,
}

// resourceGroups are all of the core Kubernetes and Cilium resource groups
// which the Cilium agent watches to implement CNI functionality.
func allResourceGroups(logger *slog.Logger, cfg watchers.WatcherConfiguration) (resourceGroups, waitForCachesOnly []string) {
	k8sGroups := []string{
		// Pods can contain labels which are essential for endpoints
		// being restored to have the right identity.
		resources.K8sAPIGroupPodV1Core,
	}

	if cfg.K8sNetworkPolicyEnabled() {
		// When the flag is set,
		// We need all network policies in place before restoring to
		// make sure we are enforcing the correct policies for each
		// endpoint before restarting.
		waitForCachesOnly = append(waitForCachesOnly, resources.K8sAPIGroupNetworkingV1Core)
	}

	ciliumGroups, waitOnlyList := watchers.GetGroupsForCiliumResources(logger, k8sSynced.AgentCRDResourceNames())
	waitForCachesOnly = append(waitForCachesOnly, waitOnlyList...)

	return append(k8sGroups, ciliumGroups...), waitForCachesOnly
}

// kvstoreExtraOptions provides the extra options to initialize the kvstore client.
func kvstoreExtraOptions(in struct {
	cell.In

	Logger *slog.Logger

	NodeManager nodeManager.NodeManager
	ClientSet   k8sClient.Clientset
	Resolver    dial.Resolver
},
) (kvstore.ExtraOptions, kvstore.BootstrapStat) {
	goopts := kvstore.ExtraOptions{
		ClusterSizeDependantInterval: in.NodeManager.ClusterSizeDependantInterval,
	}

	// If K8s is enabled we can do the service translation automagically by
	// looking at services from k8s and retrieve the service IP from that.
	// This makes cilium to not depend on kube dns to interact with etcd
	if in.ClientSet.IsEnabled() {
		goopts.DialOption = []grpc.DialOption{
			grpc.WithContextDialer(dial.NewContextDialer(in.Logger, in.Resolver)),
		}
	}

	return goopts, &bootstrapStats.kvstore
}

// kvstoreLocksGC registers the kvstore locks GC logic.
func kvstoreLocksGC(logger *slog.Logger, jg job.Group, client kvstore.Client) {
	if client.IsEnabled() {
		jg.Add(job.Timer("kvstore-locks-gc", func(ctx context.Context) error {
			kvstore.RunLockGC(logger)
			return nil
		}, defaults.KVStoreStaleLockTimeout))
	}
}
