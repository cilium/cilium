// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/api/v1/models"
	endpointapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/identity"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/metrics"
	monitoragent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

// Cell provides the EndpointManager which maintains the collection of locally
// running Cilium endpoints. Also exposed are EndpointsLookup and
// EndpointsModify APIs that EndpointManager implements. If possible, choose
// the minimal API as your dependency.
var Cell = cell.Module(
	"endpoint-manager",
	"Manages the collection of local endpoints",

	cell.Config(defaultEndpointManagerConfig),
	cell.Provide(newDefaultEndpointManager),
	cell.Provide(endpoint.NewEndpointBuildQueue),
	cell.ProvidePrivate(newEndpointSynchronizer),
	cell.Invoke(
		registerNamespaceUpdater,
	),
)

type EndpointsLookup interface {
	// Lookup looks up endpoint by prefix ID
	Lookup(id string) (*endpoint.Endpoint, error)

	// LookupCiliumID looks up endpoint by endpoint ID
	LookupCiliumID(id uint16) *endpoint.Endpoint

	// LookupCNIAttachmentID looks up endpoint by CNI attachment ID
	LookupCNIAttachmentID(id string) *endpoint.Endpoint

	// LookupIPv4 looks up endpoint by IPv4 address
	LookupIPv4(ipv4 string) *endpoint.Endpoint

	// LookupIPv6 looks up endpoint by IPv6 address
	LookupIPv6(ipv6 string) *endpoint.Endpoint

	// LookupIP looks up endpoint by IP address
	LookupIP(ip netip.Addr) (ep *endpoint.Endpoint)

	// LookupCEPName looks up endpoints by namespace + cep name, e.g. "prod/cep-0"
	LookupCEPName(name string) (ep *endpoint.Endpoint)

	// GetEndpointsByPodName looks up endpoints by namespace + pod name, e.g. "prod/pod-0"
	GetEndpointsByPodName(name string) []*endpoint.Endpoint

	// GetEndpointsByContainerID looks up endpoints by container ID
	GetEndpointsByContainerID(containerID string) []*endpoint.Endpoint

	// GetEndpointsByServiceAccount looks up endpoints by their given namespace,
	// service account pair.
	GetEndpointsByServiceAccount(namespace string, serviceAccount string) []*endpoint.Endpoint

	// GetEndpointsByNamespace looks up endpoints by namespace.
	GetEndpointsByNamespace(namespace string) []*endpoint.Endpoint

	// GetEndpoints returns a slice of all endpoints present in endpoint manager.
	GetEndpoints() []*endpoint.Endpoint

	// GetEndpointList returns a slice of all endpoint models.
	GetEndpointList(params endpointapi.GetEndpointParams) []*models.Endpoint

	// EndpointExists returns whether the endpoint with id exists.
	EndpointExists(id uint16) bool

	// GetHostEndpoint returns the host endpoint.
	GetHostEndpoint() *endpoint.Endpoint

	// HostEndpointExists returns true if the host endpoint exists.
	HostEndpointExists() bool

	// GetIngressEndpoint returns the ingress endpoint.
	GetIngressEndpoint() *endpoint.Endpoint

	// IngressEndpointExists returns true if the ingress endpoint exists.
	IngressEndpointExists() bool
}

type EndpointsModify interface {
	// AddEndpoint takes the prepared endpoint object and starts managing it.
	AddEndpoint(ep *endpoint.Endpoint) (err error)

	// RestoreEndpoint exposes the specified endpoint to other subsystems via the
	// manager.
	RestoreEndpoint(ep *endpoint.Endpoint) error

	// UpdateReferences updates maps the contents of mappings to the specified endpoint.
	UpdateReferences(ep *endpoint.Endpoint) error

	// RemoveEndpoint stops the active handling of events by the specified endpoint,
	// and prevents the endpoint from being globally accessible via other packages.
	RemoveEndpoint(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error
}

type EndpointManager interface {
	EndpointsLookup
	EndpointsModify
	EndpointResourceSynchronizer

	// Subscribe to endpoint events.
	Subscribe(s Subscriber)

	// Unsubscribe from endpoint events.
	Unsubscribe(s Subscriber)

	// UpdatePolicyMaps returns a WaitGroup which is signaled upon once all endpoints
	// have had their PolicyMaps updated against the Endpoint's desired policy state.
	//
	// Endpoints will wait on the 'notifyWg' parameter before updating policy maps.
	UpdatePolicyMaps(ctx context.Context, notifyWg *sync.WaitGroup) *sync.WaitGroup

	// RegenerateAllEndpoints calls a setState for each endpoint and
	// regenerates if state transaction is valid. During this process, the endpoint
	// list is locked and cannot be modified.
	// Returns a waiting group that can be used to know when all the endpoints are
	// regenerated.
	RegenerateAllEndpoints(regenMetadata *regeneration.ExternalRegenerationMetadata) *sync.WaitGroup

	// TriggerRegenerateAlEndpoints triggers a batched regeneration of all endpoints.
	// Returns immediately.
	TriggerRegenerateAllEndpoints()

	// OverrideEndpointOpts applies the given options to all endpoints.
	OverrideEndpointOpts(om option.OptionMap)

	// InitHostEndpointLabels initializes the host endpoint's labels with the
	// node's known labels.
	InitHostEndpointLabels(ctx context.Context)

	// UpdatePolicy triggers policy updates for all live endpoints.
	// Endpoints with security IDs in provided set will be regenerated. Otherwise, the endpoint's
	// policy revision will be bumped to toRev.
	UpdatePolicy(idsToRegen *set.Set[identity.NumericIdentity], fromRev, toRev uint64)
}

// EndpointResourceSynchronizer is an interface which synchronizes CiliumEndpoint
// resources with Kubernetes.
type EndpointResourceSynchronizer interface {
	RunK8sCiliumEndpointSync(ep *endpoint.Endpoint, hr cell.Health)
	DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint)
}

var (
	_ EndpointsLookup = &endpointManager{}
	_ EndpointsModify = &endpointManager{}
	_ EndpointManager = &endpointManager{}
)

type endpointManagerParams struct {
	cell.In

	Logger *slog.Logger

	JobGroup        job.Group
	Lifecycle       cell.Lifecycle
	Config          EndpointManagerConfig
	Clientset       client.Clientset
	MetricsRegistry *metrics.Registry
	Health          cell.Health
	EPSynchronizer  EndpointResourceSynchronizer
	LocalNodeStore  *node.LocalNodeStore
	MonitorAgent    monitoragent.Agent

	EPRestorerPromise promise.Promise[endpointstate.Restorer]
}

type endpointManagerOut struct {
	cell.Out

	Lookup   EndpointsLookup
	Modify   EndpointsModify
	Manager  EndpointManager
	Callback PolicyUpdateCallbackManager
}

func newDefaultEndpointManager(p endpointManagerParams) endpointManagerOut {
	checker := endpoint.CheckHealth

	p.Config.Validate(p.Logger)

	mgr := New(p.Logger, p.MetricsRegistry, p.EPSynchronizer, p.LocalNodeStore, p.Health, p.MonitorAgent, p.Config)

	p.Lifecycle.Append(cell.Hook{
		OnStop: func(cell.HookContext) error {
			// Stop all endpoints (its goroutines) on exit.
			mgr.stopEndpoints()
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())

	p.JobGroup.Add(job.OneShot("init-periodic-endpoint-controllers", func(jobCtx context.Context, health cell.Health) error {
		p.Logger.Debug("Waiting for endpoint restoration before registering periodic endpoint controllers (GC/regeneration)")
		epRestorer, err := p.EPRestorerPromise.Await(jobCtx)
		if err != nil {
			return fmt.Errorf("failed to wait for endpoint restorer: %w", err)
		}

		if err := epRestorer.WaitForEndpointRestore(jobCtx); err != nil {
			return fmt.Errorf("failed to wait for endpoint restoration: %w", err)
		}

		if p.Config.EndpointGCInterval > 0 {
			p.Logger.Debug("Registering periodic endpoint GC controller")
			mgr.WithPeriodicEndpointGC(ctx, checker, p.Config.EndpointGCInterval)
		}

		if p.Config.EndpointRegenInterval > 0 {
			p.Logger.Debug("Registering periodic endpoint regeneration controller")
			mgr.WithPeriodicEndpointRegeneration(ctx, p.Config.EndpointRegenInterval)
		}

		return nil
	}, job.WithShutdown()))

	p.Lifecycle.Append(cell.Hook{
		OnStop: func(cell.HookContext) error {
			cancel()
			mgr.controllers.RemoveAllAndWait()
			return nil
		},
	})

	mgr.InitMetrics(p.MetricsRegistry)

	return endpointManagerOut{
		Lookup:   mgr,
		Modify:   mgr,
		Manager:  mgr,
		Callback: mgr,
	}
}

type endpointSynchronizerParams struct {
	cell.In

	Clientset           client.Clientset
	CiliumEndpoint      resource.Resource[*types.CiliumEndpoint]
	CiliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	LocalNodeStore      *node.LocalNodeStore
}

func newEndpointSynchronizer(p endpointSynchronizerParams) EndpointResourceSynchronizer {
	return &EndpointSynchronizer{
		Clientset:           p.Clientset,
		CiliumEndpoint:      p.CiliumEndpoint,
		CiliumEndpointSlice: p.CiliumEndpointSlice,
		localNodeStore:      p.LocalNodeStore,
	}
}
