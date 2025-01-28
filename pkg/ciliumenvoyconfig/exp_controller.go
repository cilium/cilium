// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"slices"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	envoy_config_core "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_endpoint "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/cilium/stream"
	"k8s.io/apimachinery/pkg/util/sets"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

type cecControllerParams struct {
	cell.In

	DB             *statedb.DB
	JobGroup       job.Group
	Log            *slog.Logger
	ExpConfig      experimental.Config
	LocalNodeStore *node.LocalNodeStore

	NodeLabels     *nodeLabels
	CECs           statedb.RWTable[*CEC]
	EnvoyResources statedb.RWTable[*EnvoyResource]
	Writer         *experimental.Writer
	Services       statedb.Table[*experimental.Service]
	Backends       statedb.Table[*experimental.Backend]
}

type cecController struct {
	cecControllerParams

	revisions map[CECName]revisions
}

func newNodeLabels() *nodeLabels {
	nl := &nodeLabels{}
	lbls := map[string]string{}
	nl.Store(&lbls)
	return nl
}

func registerCECController(params cecControllerParams) {
	if !params.ExpConfig.EnableExperimentalLB {
		return
	}

	c := &cecController{
		cecControllerParams: params,
		revisions:           map[CECName]revisions{},
	}
	params.JobGroup.Add(job.OneShot("node-label-controller", c.nodeLabelController))
	params.JobGroup.Add(job.OneShot("resources-controller", c.processLoop))
}

// nodeLabelController updates the [SelectsLocalNode] when node labels change.
func (c *cecController) nodeLabelController(ctx context.Context, health cell.Health) error {
	localNodeChanges := stream.ToChannel(ctx, c.LocalNodeStore)

	for localNode := range localNodeChanges {
		newLabels := localNode.Labels
		oldLabels := *c.NodeLabels.Load()

		if !maps.Equal(newLabels, oldLabels) {
			c.Log.Debug("Labels changed", "old", oldLabels, "new", newLabels)

			// Since the labels changed, recompute 'SelectsLocalNode'
			// for all CECs.
			wtxn := c.DB.WriteTxn(c.CECs)

			// Store the new labels so the reflector can compute 'SelectsLocalNode'
			// on the fly. The reflector may already update 'SelectsLocalNode' to the
			// correct value, so the recomputation that follows may be duplicate for
			// some CECs, but that's fine. This is updated with the CEC table lock held
			// and read by CEC reflector with the table lock which ensures consistency.
			// With the Table[Node] changes in https://github.com/cilium/cilium/pull/32144
			// this can be removed and we can instead read the labels directly from the node
			// table.
			labelSet := labels.Set(newLabels)
			c.NodeLabels.Store(&newLabels)

			for cec := range c.CECs.All(wtxn) {
				if cec.Selector != nil {
					selects := cec.Selector.Matches(labelSet)
					if selects != cec.SelectsLocalNode {
						cec = cec.Clone()
						cec.SelectsLocalNode = selects
						c.CECs.Insert(wtxn, cec)
					}
				}
			}
			wtxn.Commit()
		}
	}
	return nil
}

func getProxyRedirect(cec *CEC, svcl *ciliumv2.ServiceListener) *experimental.ProxyRedirect {
	var port uint16
	if svcl.Listener != "" {
		// Listener names are qualified after parsing, so qualify the listener reference as well for it to match
		svcListener, _ := api.ResourceQualifiedName(
			cec.Name.Namespace, cec.Name.Name, svcl.Listener, api.ForceNamespace)
		port, _ = cec.Listeners.Get(svcListener)
	} else {
		for _, p := range cec.Listeners.All() {
			port = p
			break
		}
	}
	if port == 0 {
		return nil
	}
	return &experimental.ProxyRedirect{
		ProxyPort: port,
		Ports:     svcl.Ports,
	}
}

func (c *cecController) processLoop(ctx context.Context, health cell.Health) error {
	ws := statedb.NewWatchSet()
	existing := sets.New[CECName]()
	limiter := rate.NewLimiter(100*time.Millisecond, 1)
	for {
		wtxn := c.DB.WriteTxn(c.EnvoyResources)

		// Process all CiliumEnvoyConfigs to compute the new EnvoyResources.
		cecs, watch := c.CECs.AllWatch(wtxn)
		ws.Add(watch)
		processed := sets.New[CECName]()
		for cec, rev := range cecs {
			c.processCEC(wtxn, ws, cec, rev)
			processed.Insert(cec.Name)
			existing.Delete(cec.Name)
		}

		// Remove orphaned envoy resources.
		for orphan := range existing {
			c.EnvoyResources.Delete(wtxn, &EnvoyResource{Name: orphan})
			delete(c.revisions, orphan)
		}
		existing = processed
		wtxn.Commit()

		// Wait for any of the queries we made to invalidate before
		// recomputing again.
		if err := ws.Wait(ctx); err != nil {
			return err
		}

		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}
}

func (c *cecController) processCEC(wtxn statedb.WriteTxn, ws *statedb.WatchSet, cec *CEC, rev statedb.Revision) {
	if !cec.SelectsLocalNode && c.revisions[cec.Name].cecRevision != rev {
		c.EnvoyResources.Delete(
			wtxn,
			&EnvoyResource{Name: cec.Name},
		)
		c.revisions[cec.Name] = revisions{cecRevision: rev}
		return
	}

	assignments := map[string]*envoy_config_endpoint.ClusterLoadAssignment{}
	redirects, revisions, updated := c.processSpec(
		wtxn,
		ws,
		cec,
		rev,
		c.revisions[cec.Name],
		assignments,
	)
	if !updated {
		return
	}

	c.revisions[cec.Name] = revisions

	// Shallow copy of Resources is enough as we just set the Endpoints field.
	resources := cec.Resources

	resources.Endpoints = make([]*envoy_config_endpoint.ClusterLoadAssignment, 0, len(assignments))
	for _, key := range slices.Sorted(maps.Keys(assignments)) {
		resources.Endpoints = append(resources.Endpoints, assignments[key])
	}

	c.EnvoyResources.Modify(
		wtxn,
		&EnvoyResource{
			Name:      cec.Name,
			Resources: resources,
			Redirects: redirects,
			Status:    reconciler.StatusPending(),
		},
		func(old, new *EnvoyResource) *EnvoyResource {
			if old != nil {
				new.ReconciledResources = old.ReconciledResources
				new.ReconciledRedirects = old.ReconciledRedirects
			}
			return new
		},
	)
}

func (c *cecController) processSpec(
	txn statedb.ReadTxn,
	ws *statedb.WatchSet,
	cec *CEC,
	cecRevision statedb.Revision,
	prevRevisions revisions,
	assignments map[string]*envoy_config_endpoint.ClusterLoadAssignment,
) (map[loadbalancer.ServiceName]*experimental.ProxyRedirect, revisions, bool) {
	redirects := map[loadbalancer.ServiceName]*experimental.ProxyRedirect{}
	servicePorts := map[loadbalancer.ServiceName]sets.Set[string]{}

	for _, l := range cec.Spec.Services {
		ports := servicePorts[l.ServiceName()]
		if ports == nil {
			ports = sets.New[string]()
			servicePorts[l.ServiceName()] = ports
		}
		for _, p := range l.Ports {
			ports.Insert(strconv.Itoa(int(p)))
		}
		redirects[l.ServiceName()] = getProxyRedirect(cec, l)
	}

	for _, l := range cec.Spec.BackendServices {
		ports := servicePorts[l.ServiceName()]
		if ports == nil {
			ports = sets.New[string]()
			servicePorts[l.ServiceName()] = ports
		}
		for _, p := range l.Ports {
			ports.Insert(p)
		}
	}

	// The deferred load assignment computations. Only ran if the input object
	// revisions have changed.
	var computations []func()

	revisions := revisions{
		cecRevision: cecRevision,
		services:    map[loadbalancer.ServiceName]statedb.Revision{},
		backends:    map[loadbalancer.L3n4Addr]statedb.Revision{},
	}

	for name, ports := range servicePorts {
		svc, rev, watchSvc, found := c.Services.GetWatch(txn, experimental.ServiceByName(name))
		ws.Add(watchSvc)
		revisions.services[name] = rev

		if !found {
			continue
		}
		bes, watchBes := c.Backends.ListWatch(txn, experimental.BackendByServiceName(svc.Name))
		ws.Add(watchBes)

		for be, rev := range bes {
			revisions.backends[be.L3n4Addr] = rev
		}
		computations = append(computations, func() {
			computeLoadAssignments(
				assignments,
				svc.Name,
				ports,
				svc.PortNames,
				bes)
		})
	}

	if prevRevisions.equal(revisions) {
		// Nothing has changed.
		return redirects, revisions, false
	}

	// Recompute the load assignments.
	for _, compute := range computations {
		compute()
	}
	return redirects, revisions, true
}

func computeLoadAssignments(
	assignments map[string]*envoy_config_endpoint.ClusterLoadAssignment,
	serviceName loadbalancer.ServiceName,
	ports sets.Set[string],
	portNames map[string]uint16,
	backends iter.Seq2[*experimental.Backend, statedb.Revision],
) {
	// Partition backends by port name.
	backendMap := map[string]map[string]*experimental.Backend{}

	for be := range backends {
		inst := be.GetInstance(serviceName)
		portName := anyPort

		// If ports are specified only pick the backends that match the service port name or number.
		if ports.Len() > 0 {
			switch {
			case inst.PortName == "":
			case ports.Has(inst.PortName):
				portName = inst.PortName
			default:
				port, found := portNames[inst.PortName]
				if !found {
					continue
				}
				portS := strconv.FormatUint(uint64(port), 10)
				// Try looking up by port number
				if !ports.Has(portS) {
					continue
				}
				portName = portS
			}
		}
		if be.State != loadbalancer.BackendStateActive {
			continue
		}
		backends := backendMap[portName]
		if backends == nil {
			backends = map[string]*experimental.Backend{}
			backendMap[portName] = backends
		}
		backends[be.L3n4Addr.String()] = be
	}

	for _, port := range slices.Sorted(maps.Keys(backendMap)) {
		bes := backendMap[port]
		var lbEndpoints []*envoy_config_endpoint.LbEndpoint
		for _, addr := range slices.Sorted(maps.Keys(bes)) {
			be := bes[addr]

			// The below is to make sure that UDP and SCTP are not allowed instead of comparing with lb.TCP
			// The reason is to avoid extra dependencies with ongoing work to differentiate protocols in datapath,
			// which might add more values such as lb.Any, lb.None, etc.
			if be.Protocol == loadbalancer.UDP || be.Protocol == loadbalancer.SCTP {
				continue
			}

			lbEndpoints = append(lbEndpoints, &envoy_config_endpoint.LbEndpoint{
				HostIdentifier: &envoy_config_endpoint.LbEndpoint_Endpoint{
					Endpoint: &envoy_config_endpoint.Endpoint{
						Address: &envoy_config_core.Address{
							Address: &envoy_config_core.Address_SocketAddress{
								SocketAddress: &envoy_config_core.SocketAddress{
									Address: be.AddrCluster.String(),
									PortSpecifier: &envoy_config_core.SocketAddress_PortValue{
										PortValue: uint32(be.Port),
									},
								},
							},
						},
					},
				},
			})
		}

		endpoint := &envoy_config_endpoint.ClusterLoadAssignment{
			ClusterName: fmt.Sprintf("%s:%s", serviceName.String(), port),
			Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{
				{
					LbEndpoints: lbEndpoints,
				},
			},
		}
		assignments[endpoint.ClusterName] = endpoint

		// for backward compatibility, if any port is allowed, publish one more
		// endpoint having cluster name as service name.
		if port == anyPort {
			assignments[serviceName.String()] =
				&envoy_config_endpoint.ClusterLoadAssignment{
					ClusterName: serviceName.String(),
					Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{
						{
							LbEndpoints: lbEndpoints,
						},
					},
				}
		}
	}
}

// revisions tracks the object revisions used to compute the EnvoyResource from a
// CiliumEnvoyConfig. The EnvoyResource is only recomputed if there's a difference
// in the revisions.
type revisions struct {
	cecRevision statedb.Revision
	services    map[loadbalancer.ServiceName]statedb.Revision
	backends    map[loadbalancer.L3n4Addr]statedb.Revision
}

func (r revisions) equal(other revisions) bool {
	return r.cecRevision == other.cecRevision && maps.Equal(r.services, other.services) && maps.Equal(r.backends, other.backends)
}
