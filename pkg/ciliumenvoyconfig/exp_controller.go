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
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
)

type cecControllerParams struct {
	cell.In

	DB             *statedb.DB
	JobGroup       job.Group
	Log            *slog.Logger
	ExpConfig      experimental.Config
	LocalNodeStore *node.LocalNodeStore
	Metrics        experimentalMetrics

	NodeLabels     *nodeLabels
	CECs           statedb.RWTable[*CEC]
	EnvoyResources statedb.RWTable[*EnvoyResource]
	Writer         *experimental.Writer
	Services       statedb.Table[*experimental.Service]
	Backends       statedb.Table[*experimental.Backend]
}

type cecController struct {
	cecControllerParams
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
			c.Log.Debug("Labels changed",
				logfields.Old, oldLabels,
				logfields.New, newLabels,
			)

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
	cecWatchSets := map[CECName]*statedb.WatchSet{}
	clusterWatchSets := map[loadbalancer.ServiceName]*statedb.WatchSet{}
	var closedWatches []<-chan struct{}
	orphans := sets.New[CECName]()

	for {
		t0 := time.Now()
		wtxn := c.DB.WriteTxn(c.EnvoyResources)

		// Process all Cilium(ClusterWide)EnvoyConfigs to compute the new EnvoyResources.
		// We use the [statedb.WatchSet] to figure out which things to recompute. If any
		// of the queries made for a particular CEC changes we recompute the Envoy resources
		// for it.
		allWatches := statedb.NewWatchSet()

		cecs, watch := c.CECs.AllWatch(wtxn)
		allWatches.Add(watch)
		existing := sets.New[CECName]()
		for cec := range cecs {
			if !cec.SelectsLocalNode {
				continue
			}

			existing.Insert(cec.Name)
			orphans.Delete(cec.Name)

			if ws, found := cecWatchSets[cec.Name]; found {
				if !ws.HasAny(closedWatches) {
					// Queries related to this CEC did not change, skip.
					allWatches.Merge(ws)
					continue
				}
			}
			watchSet := c.processCEC(wtxn, cec.Name)
			if watchSet != nil {
				allWatches.Merge(watchSet)
				cecWatchSets[cec.Name] = watchSet

				// Force process all referenced cluster resources.
				for svcName := range cec.ServicePorts {
					delete(clusterWatchSets, svcName)
				}
			}
		}

		// Remove orphaned envoy resources.
		for orphan := range orphans {
			old, found, _ := c.EnvoyResources.Delete(wtxn, &EnvoyResource{
				Name: EnvoyResourceName{Kind: EnvoyResourceKindListener, Namespace: orphan.Namespace, Name: orphan.Name},
			})
			if found {
				// Update cluster resource references.
				for svcName := range old.Listener.ServicePorts {
					if c.removeClusterReference(wtxn, orphan, svcName) {
						// Delete the watch set to force it to be processed.
						delete(clusterWatchSets, svcName)
					}
				}
			}
			delete(cecWatchSets, orphan)
		}

		// Update cluster resources.
		for res := range c.EnvoyResources.List(wtxn, EnvoyResourceByKind(EnvoyResourceKindEndpoints)) {
			if ws, found := clusterWatchSets[res.ClusterServiceName()]; found {
				if !ws.HasAny(closedWatches) {
					// Queries related to this did not change, skip.
					allWatches.Merge(ws)
					continue
				}
			}

			if len(res.Cluster.References) == 0 {
				// No CEC references this cluster resource. We can delete it.
				c.EnvoyResources.Delete(wtxn, res)
				delete(clusterWatchSets, res.ClusterServiceName())
				continue
			}

			ws := statedb.NewWatchSet()
			clusterWatchSets[res.ClusterServiceName()] = ws

			res = res.Clone()

			// Look up the referenced service for the port name to port number mappings.
			svc, _, watchSvc, found := c.Services.GetWatch(wtxn, experimental.ServiceByName(res.ClusterServiceName()))
			ws.Add(watchSvc)
			if found {
				// Look up associated backends and update the load assignments.
				bes, watchBes := c.Writer.BackendsForService(wtxn, svc.Name)
				ws.Add(watchBes)
				res.Resources.Endpoints = computeLoadAssignments(
					svc.Name,
					res.Cluster.References,
					svc.PortNames,
					c.Writer.SelectBackends(bes, svc, nil))
			} else {
				// No service found (yet) and thus there are no endpoints.
				res.Resources.Endpoints = nil
			}

			res.Status = reconciler.StatusPending()
			c.EnvoyResources.Insert(wtxn, res)

			allWatches.Merge(ws)
		}

		wtxn.Commit()

		orphans = existing

		c.Metrics.ControllerDuration.Observe(float64(time.Since(t0)) / float64(time.Second))

		// Wait for any of the queries we made to invalidate before
		// recomputing again. [allWatches] is cleared by Wait().
		var err error
		closedWatches, err = allWatches.Wait(ctx, 100*time.Millisecond)
		if err != nil {
			return err
		}
	}
}

func (c *cecController) processCEC(wtxn statedb.WriteTxn, cecName CECName) *statedb.WatchSet {
	cec, _, watch, found := c.CECs.GetWatch(wtxn, CECByName(cecName))
	if !found {
		return nil
	}
	ws := statedb.NewWatchSet()
	ws.Add(watch)

	redirects := map[loadbalancer.ServiceName]*experimental.ProxyRedirect{}
	for _, l := range cec.Spec.Services {
		redirects[l.ServiceName()] = getProxyRedirect(cec, l)

		// Watch changes for each of the referenced services to make sure we reprocess the CEC
		// and set the ProxyRedirect in cases where CEC was created before the Service.
		_, _, watchSvc, _ := c.Services.GetWatch(wtxn, experimental.ServiceByName(l.ServiceName()))
		ws.Add(watchSvc)
	}

	// Update/create the "cluster" resources. For each referenced service we'll have an EnvoyResource
	// to which the endpoints are added. This is then reconciled separately from the "listener" resource
	// we create below.
	for svcName, ports := range cec.ServicePorts {
		resName := EnvoyResourceName{
			Kind:      EnvoyResourceKindEndpoints,
			Cluster:   svcName.Cluster,
			Namespace: svcName.Namespace,
			Name:      svcName.Name,
		}

		res, _, found := c.EnvoyResources.Get(wtxn, EnvoyResourceByName(resName))
		if found {
			res = res.Clone()
		} else {
			res = &EnvoyResource{Name: resName}
		}
		res.Cluster.References = res.Cluster.References.Add(cec.Name, ports)
		c.EnvoyResources.Insert(wtxn, res)
	}

	// Create or update the "listener" resource.
	resName := EnvoyResourceName{Kind: EnvoyResourceKindListener, Namespace: cec.Name.Namespace, Name: cec.Name.Name}
	new := &EnvoyResource{
		Name:      resName,
		Resources: cec.Resources,
		Listener: EnvoyResourceListener{
			Redirects:    redirects,
			ServicePorts: cec.ServicePorts,
		},
		Status: reconciler.StatusPending(),
	}
	if old, _, found := c.EnvoyResources.Get(wtxn, EnvoyResourceByName(resName)); found {
		new.ReconciledResources = old.ReconciledResources
		new.Listener.ReconciledRedirects = old.Listener.ReconciledRedirects

		for svcName := range old.Listener.ServicePorts {
			_, found := new.Listener.ServicePorts[svcName]
			if !found {
				c.removeClusterReference(wtxn, cec.Name, svcName)
			}
		}
	}
	c.EnvoyResources.Insert(wtxn, new)

	// Return the watch set. When any of the channels in the set closes we will
	// reprocess this CEC.
	return ws
}

func (c *cecController) removeClusterReference(wtxn statedb.WriteTxn, cecName CECName, svcName loadbalancer.ServiceName) bool {
	res, _, found := c.EnvoyResources.Get(wtxn, EnvoyResourceByName(EnvoyResourceName{
		Kind:      EnvoyResourceKindEndpoints,
		Cluster:   svcName.Cluster,
		Namespace: svcName.Namespace,
		Name:      svcName.Name,
	}))
	if found {
		newRefs := res.Cluster.References.Remove(cecName)
		if len(newRefs) == 0 {
			c.EnvoyResources.Delete(wtxn, res)
		} else {
			res = res.Clone()
			res.Cluster.References = newRefs
			c.EnvoyResources.Insert(wtxn, res)
			return true
		}
	}
	return false
}

func computeLoadAssignments(
	serviceName loadbalancer.ServiceName,
	clusterRefs clusterReferences,
	portNames map[string]uint16,
	backends iter.Seq2[experimental.BackendParams, statedb.Revision],
) (assignments []*envoy_config_endpoint.ClusterLoadAssignment) {
	// Partition backends by port name.
	backendMap := map[string]map[string]experimental.BackendParams{}

	// Union of all port names from all referencing CECs.
	ports := sets.New[string]()
	for _, ref := range clusterRefs {
		for p := range ref.PortNames {
			ports.Insert(p)
		}
	}

	for be := range backends {
		if be.State != loadbalancer.BackendStateActive || be.Unhealthy {
			// Skip non-active or unhealthy backends.
			continue
		}

		bePortNames := []string{anyPort}

		// If ports are specified only pick the backends that match the service port name or number.
		if len(ports) > 0 {
			bePortNames = bePortNames[:0]
			if len(be.PortNames) == 0 {
				// Backend without a port name will match with the
				// nameless port in the service.
				for name, number := range portNames {
					if name != "" {
						continue
					}
					portS := strconv.FormatUint(uint64(number), 10)
					if ports.Has(portS) {
						bePortNames = append(bePortNames, portS)
					}
				}
			} else {
				// Backend has port name(s), try to match them up
				// against the filter ports. We try to match both
				// by name and by port number.
				for _, portName := range be.PortNames {
					if ports.Has(portName) {
						bePortNames = append(bePortNames, portName)
						continue
					}

					// The "name" not found from ports, see if the
					// "number" can be found.
					port, found := portNames[portName]
					if !found {
						continue
					}
					portS := strconv.FormatUint(uint64(port), 10)
					// Try looking up by port number
					if !ports.Has(portS) {
						continue
					}
					bePortNames = append(bePortNames, portS)
				}
			}
		}
		for _, portName := range bePortNames {
			backends := backendMap[portName]
			if backends == nil {
				backends = map[string]experimental.BackendParams{}
				backendMap[portName] = backends
			}
			backends[be.Address.String()] = be
		}
	}

	for _, port := range slices.Sorted(maps.Keys(backendMap)) {
		bes := backendMap[port]
		var lbEndpoints []*envoy_config_endpoint.LbEndpoint
		for _, addr := range slices.Sorted(maps.Keys(bes)) {
			be := bes[addr]

			// The below is to make sure that UDP and SCTP are not allowed instead of comparing with lb.TCP
			// The reason is to avoid extra dependencies with ongoing work to differentiate protocols in datapath,
			// which might add more values such as lb.Any, lb.None, etc.
			if be.Address.Protocol == loadbalancer.UDP || be.Address.Protocol == loadbalancer.SCTP {
				continue
			}

			lbEndpoints = append(lbEndpoints, &envoy_config_endpoint.LbEndpoint{
				HostIdentifier: &envoy_config_endpoint.LbEndpoint_Endpoint{
					Endpoint: &envoy_config_endpoint.Endpoint{
						Address: &envoy_config_core.Address{
							Address: &envoy_config_core.Address_SocketAddress{
								SocketAddress: &envoy_config_core.SocketAddress{
									Address: be.Address.AddrCluster.String(),
									PortSpecifier: &envoy_config_core.SocketAddress_PortValue{
										PortValue: uint32(be.Address.Port),
									},
								},
							},
						},
					},
				},
			})
		}

		endpoints := []*envoy_config_endpoint.LocalityLbEndpoints{{LbEndpoints: lbEndpoints}}
		assignments = append(assignments,
			&envoy_config_endpoint.ClusterLoadAssignment{
				ClusterName: fmt.Sprintf("%s:%s", serviceName.String(), port),
				Endpoints:   endpoints,
			})

		// for backward compatibility, if any port is allowed, publish one more
		// endpoint having cluster name as service name.
		if port == anyPort {
			assignments = append(assignments,
				&envoy_config_endpoint.ClusterLoadAssignment{
					ClusterName: serviceName.String(),
					Endpoints:   endpoints,
				})
		}
	}
	return
}
