// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/sirupsen/logrus"

	healthApi "github.com/cilium/cilium/api/v1/health/server"
	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/daemon/cmd/cni"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/daemon/restapi"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/auth"
	"github.com/cilium/cilium/pkg/bgpv1"
	"github.com/cilium/cilium/pkg/clustermesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/egressgateway"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	ipamMetadata "github.com/cilium/cilium/pkg/ipam/metadata"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/l2announcer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/signal"
	"github.com/cilium/cilium/pkg/statedb"
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
		pprof.Cell,
		cell.Config(pprof.Config{
			PprofAddress: option.PprofAddressAgent,
			PprofPort:    option.PprofPortAgent,
		}),

		// Runs the gops agent, a tool to diagnose Go processes.
		gops.Cell(defaults.GopsPortAgent),

		// Provides Clientset, API for accessing Kubernetes objects.
		k8sClient.Cell,

		cni.Cell,

		// Provide the modular metrics registry, metric HTTP server and legacy metrics cell.
		metrics.Cell,

		// Provides cilium_datapath_drop/forward Prometheus metrics.
		metricsmap.Cell,

		// Provide option.Config via hive so cells can depend on the agent config.
		cell.Provide(func() *option.DaemonConfig { return option.Config }),

		// Provides a global job registry which cells can use to spawn job groups.
		job.Cell,

		// Cilium API served over UNIX sockets. Accessed by the 'cilium' utility (not cilium-cli).
		server.Cell,
		cell.Invoke(configureAPIServer),

		// Cilium API handlers
		cell.Provide(ciliumAPIHandlers),

		// Processes endpoint deletions that occurred while the agent was down.
		// This starts before the API server as ciliumAPIHandlers() depends on
		// the 'deletionQueue' provided by this cell.
		deletionQueueCell,

		// DB provides an extendable in-memory database with rich transactions
		// and multi-version concurrency control through immutable radix trees.
		statedb.Cell,
		// Store cell provides factory for creating watchStore/syncStore/storeManager
		// useful for synchronizing data from/to kvstore.
		store.Cell,
	)

	// ControlPlane implement the per-node control functions. These are pure
	// business logic and depend on datapath or infrastructure to perform
	// actions. This separation enables non-privileged integration testing of
	// the control-plane.
	ControlPlane = cell.Module(
		"controlplane",
		"Control Plane",

		// LocalNodeStore holds onto the information about the local node and allows
		// observing changes to it.
		node.LocalNodeStoreCell,

		// Provide a newLocalNodeSynchronizer that is invoked when LocalNodeStore is started.
		// This fills in the initial state before it is accessed by other sub-systems.
		// Then, it takes care of keeping selected fields (e.g., labels, annotations)
		// synchronized with the corresponding kubernetes object.
		cell.Provide(newLocalNodeSynchronizer),

		// Controller provides flags and configuration related
		// to Controller management, concurrent control loops
		// which run throughout the system on specified intervals
		controller.Cell,

		// Shared resources provide access to k8s resources as event streams or as
		// read-only stores.
		agentK8s.ResourcesCell,

		// EndpointManager maintains a collection of the locally running endpoints.
		endpointmanager.Cell,

		// NodeManager maintains a collection of other nodes in the cluster.
		nodeManager.Cell,

		// Certificate manager provides an API for retrieving secrets and certificate in the form of TLS contexts.
		certificatemanager.Cell,

		// Cilium API specification cell makes the swagger model available for reuse
		server.SpecCell,

		// cilium-health connectivity probe API specification cell makes the swagger model available for reuse
		healthApi.SpecCell,

		// daemonCell wraps the legacy daemon initialization and provides Promise[*Daemon].
		daemonCell,

		// Service is a datapath service handler. Its main responsibility is to reflect
		// service-related changes into BPF maps used by datapath BPF programs.
		service.Cell,

		// Proxy provides the proxy port allocation and related datapath coordination and
		// makes different L7 proxies (Envoy, DNS proxy) usable to Cilium endpoints through
		// a common Proxy 'redirect' abstraction.
		proxy.Cell,

		// Envoy cell which is the control-plane for the Envoy proxy.
		// It is used to provide support for Ingress, GatewayAPI and L7 network policies (e.g. HTTP).
		envoy.Cell,

		// Cilium REST API handlers
		restapi.Cell,

		// The BGP Control Plane which enables various BGP related interop.
		bgpv1.Cell,

		// Brokers datapath signals from signalmap
		signal.Cell,

		// Auth is responsible for authenticating a request if required by a policy.
		auth.Cell,

		// IPCache, policy.Repository and CachingIdentityAllocator.
		cell.Provide(newPolicyTrifecta),

		// IPAM metadata manager, determines which IPAM pool a pod should allocate from
		ipamMetadata.Cell,

		// Egress Gateway allows originating traffic from specific IPv4 addresses.
		egressgateway.Cell,

		// ServiceCache holds the list of known services correlated with the matching endpoints.
		k8s.ServiceCacheCell,

		// ClusterMesh is the Cilium's multicluster implementation.
		cell.Config(cmtypes.DefaultClusterInfo),
		clustermesh.Cell,

		// L2announcer resolves l2announcement policies, services, node labels and devices into a list of IPs+netdevs
		// which need to be announced on the local network.
		l2announcer.Cell,

		// RegeneratorCell provides extra options and utilities for endpoints regeneration.
		endpoint.RegeneratorCell,
	)
)

func configureAPIServer(cfg *option.DaemonConfig, s *server.Server, swaggerSpec *server.Spec) {
	s.EnabledListeners = []string{"unix"}
	s.SocketPath = cfg.SocketPath
	s.ReadTimeout = apiTimeout
	s.WriteTimeout = apiTimeout

	msg := "Required API option %s is disabled. This may prevent Cilium from operating correctly"
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
			log.WithFields(logrus.Fields{
				logfields.Hint:   hint,
				logfields.Params: requiredAPI,
			}).Warning(msg)
		}
	}
	api.DisableAPIs(swaggerSpec.DeniedAPIs, s.GetAPI().AddMiddlewareFor)

}
