// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"slices"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	envoy_config_core "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_endpoint "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/part"
	"github.com/cilium/statedb/reconciler"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
)

type cecControllerParams struct {
	cell.In

	DB             *statedb.DB
	JobGroup       job.Group
	ExpConfig      loadbalancer.Config
	Metrics        experimentalMetrics
	CECs           statedb.Table[*CEC]
	EnvoyResources statedb.RWTable[*EnvoyResource]
	Writer         *writer.Writer
}

// cecController processes changes to Table[CEC] and populates Table[EnvoyResource]. These
// desired envoy resources are then synced towards Envoy by the reconciler.
//
//	   <kube-apiserver> . . . . .
//	        v                    \
//	   <cecReflector>          <loadbalancer>
//	        v                   /        \
//		  Table[*CEC] Table[*Service] Table[*Backend]
//			    \       |        . . /
//			     <cecController>
//			           v
//			  Table[EnvoyResource]
//			           v
//			<envoyOps>.Update/Delete
//			           v
//			       XDS Server
type cecController struct {
	cecControllerParams
}

func registerCECController(params cecControllerParams) {
	if !params.ExpConfig.EnableExperimentalLB {
		return
	}

	c := &cecController{
		cecControllerParams: params,
	}
	params.JobGroup.Add(job.OneShot("controller", c.processLoop))
}

func getProxyRedirect(cec *CEC, svcl *ciliumv2.ServiceListener) *loadbalancer.ProxyRedirect {
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
	return &loadbalancer.ProxyRedirect{
		ProxyPort: port,
		Ports:     svcl.Ports,
	}
}

func (c *cecController) processLoop(ctx context.Context, health cell.Health) error {
	var closedWatches []<-chan struct{}
	backendProcessor := backendProcessor{
		watchSets:      map[loadbalancer.ServiceName]*statedb.WatchSet{},
		envoyResources: c.EnvoyResources,
		writer:         c.Writer,
	}
	cecProcessor := cecProcessor{
		watchSets:      map[types.NamespacedName]*statedb.WatchSet{},
		orphans:        map[types.NamespacedName]sets.Empty{},
		cecs:           c.CECs,
		writer:         c.Writer,
		envoyResources: c.EnvoyResources,
	}

	for {
		t0 := time.Now()

		// Build up a watch set from all the queries made during the processing in this round
		// so we know when to reprocess.
		allWatches := statedb.NewWatchSet()

		// Compute the new desired envoy resources that we want to sync towards Envoy.
		wtxn := c.DB.WriteTxn(c.EnvoyResources)

		// Process new and changed CECs to compute the "cec" EnvoyResources:
		// for each CEC:
		//   Upsert EnvoyResource{Origin: "cec"}
		//   for each referenced service:
		//     Upsert EnvoyResource{
		//       Origin: "backendsync",
		//       ClusterReferences: ClusterReferences + cec.Name
		//     }
		cecProcessor.process(wtxn, closedWatches, allWatches)

		// Compute the "backendsync" EnvoyResources.
		//
		// for each "backendsync" EnvoyResource:
		//   backends := BackendsForService(res.ClusterServiceName())
		//   Upsert EnvoyResource{
		//     Origin: "backendsync",
		//     Resources.Endpoints: backendsToLoadAssignments(backends),
		//   }
		backendProcessor.process(wtxn, closedWatches, allWatches)

		// Commit the new desired envoy resources. The changes will be picked up by the
		// reconciler and pushed to Envoy.
		wtxn.Commit()

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

// cecProcessor computes desired envoy resources from the CECs. It upserts a EnvoyResource
// with Origin=cec for the resources coming from [CEC] and it upserts an EnvoyResource with
// Origin=backendsync for each referenced service for which we want backends synced to Envoy.
//
// The [backendProcessor] will fill in the Endpoints into the Origin=backendsync resources
// afterwards.
type cecProcessor struct {
	watchSets      map[CECName]*statedb.WatchSet
	orphans        sets.Set[CECName]
	cecs           statedb.Table[*CEC]
	writer         *writer.Writer
	envoyResources statedb.RWTable[*EnvoyResource]
}

func (c *cecProcessor) process(wtxn statedb.WriteTxn, closedWatches []<-chan struct{}, allWatches *statedb.WatchSet) {
	cecs, watch := c.cecs.AllWatch(wtxn)
	allWatches.Add(watch)
	existing := sets.New[CECName]()
	for cec := range cecs {
		if !cec.SelectsLocalNode {
			continue
		}

		existing.Insert(cec.Name)
		c.orphans.Delete(cec.Name)

		if ws, found := c.watchSets[cec.Name]; found {
			if !ws.HasAny(closedWatches) {
				// Queries related to this CEC did not change, skip.
				allWatches.Merge(ws)
				continue
			}
		}
		watchSet := c.processCEC(wtxn, cec.Name)
		if watchSet != nil {
			allWatches.Merge(watchSet)
			c.watchSets[cec.Name] = watchSet
		}
	}

	// Remove orphaned envoy resources.
	for orphan := range c.orphans {
		old, found, _ := c.envoyResources.Delete(wtxn, &EnvoyResource{
			Name: EnvoyResourceName{Origin: EnvoyResourceOriginCEC, Namespace: orphan.Namespace, Name: orphan.Name},
		})
		if found {
			// Update cluster resource references.
			for svcName := range old.ReferencedServices.All() {
				c.removeClusterReference(wtxn, orphan, svcName)
			}
		}
		delete(c.watchSets, orphan)
	}

	c.orphans = existing

	return
}

func (c *cecProcessor) processCEC(wtxn statedb.WriteTxn, cecName CECName) *statedb.WatchSet {
	cec, _, watch, found := c.cecs.GetWatch(wtxn, CECByName(cecName))
	if !found {
		return nil
	}
	ws := statedb.NewWatchSet()
	ws.Add(watch)

	var redirects part.Map[loadbalancer.ServiceName, *loadbalancer.ProxyRedirect]
	for _, l := range cec.Spec.Services {
		redirects = redirects.Set(l.ServiceName(), getProxyRedirect(cec, l))

		// Watch changes for each of the referenced services to make sure we reprocess the CEC
		// and set the ProxyRedirect in cases where CEC was created before the Service.
		_, _, watchSvc, _ := c.writer.Services().GetWatch(wtxn, loadbalancer.ServiceByName(l.ServiceName()))
		ws.Add(watchSvc)
	}

	// Update/create the "cluster" resources. For each referenced service we'll have an EnvoyResource
	// to which the endpoints are added. This is then reconciled separately from the "listener" resource
	// we create below.
	for svcName, ports := range cec.ServicePorts {
		resName := EnvoyResourceName{
			Origin:    EnvoyResourceOriginBackendSync,
			Cluster:   svcName.Cluster,
			Namespace: svcName.Namespace,
			Name:      svcName.Name,
		}

		res, _, found := c.envoyResources.Get(wtxn, EnvoyResourceByName(resName))
		if found {
			res = res.Clone()
		} else {
			res = &EnvoyResource{Name: resName}
		}
		res.ClusterReferences = res.ClusterReferences.Add(cec.Name, ports)
		c.envoyResources.Insert(wtxn, res)
	}

	// Create or update the "listener" resource.
	resName := EnvoyResourceName{Origin: EnvoyResourceOriginCEC, Namespace: cec.Name.Namespace, Name: cec.Name.Name}
	new := &EnvoyResource{
		Name:               resName,
		Resources:          cec.Resources,
		Redirects:          redirects,
		ReferencedServices: part.NewSet(slices.Collect(maps.Keys(cec.ServicePorts))...),
		Status:             reconciler.StatusPending(),
	}
	if old, _, found := c.envoyResources.Get(wtxn, EnvoyResourceByName(resName)); found {
		new.ReconciledResources = old.ReconciledResources
		new.ReconciledRedirects = old.ReconciledRedirects

		for svcName := range old.ReferencedServices.All() {
			if !new.ReferencedServices.Has(svcName) {
				c.removeClusterReference(wtxn, cec.Name, svcName)
			}
		}
	}
	c.envoyResources.Insert(wtxn, new)

	// Return the watch set. When any of the channels in the set closes we will
	// reprocess this CEC.
	return ws
}

func (c *cecProcessor) removeClusterReference(wtxn statedb.WriteTxn, cecName CECName, svcName loadbalancer.ServiceName) {
	res, _, found := c.envoyResources.Get(wtxn, EnvoyResourceByName(EnvoyResourceName{
		Origin:    EnvoyResourceOriginBackendSync,
		Cluster:   svcName.Cluster,
		Namespace: svcName.Namespace,
		Name:      svcName.Name,
	}))
	if found {
		newRefs := res.ClusterReferences.Remove(cecName)
		if len(newRefs) == 0 {
			c.envoyResources.Delete(wtxn, res)
		} else {
			res = res.Clone()
			res.ClusterReferences = newRefs
			c.envoyResources.Insert(wtxn, res)
		}
	}
}

// backedProcessor fills in the backends into the EnvoyResources with Origin=backendsync that were created by [cecProcessor].
// These will be recomputed if any of the inputs change.
type backendProcessor struct {
	// watchSets per service name. We hold onto the watches returned by queries made when computing the backends to sync
	// per service name so we know when it needs to be recomputed.
	watchSets      map[loadbalancer.ServiceName]*statedb.WatchSet
	envoyResources statedb.RWTable[*EnvoyResource]
	writer         *writer.Writer
}

func (bs *backendProcessor) process(wtxn statedb.WriteTxn, closedWatches []<-chan struct{}, allWatches *statedb.WatchSet) {
	for res := range bs.envoyResources.List(wtxn, EnvoyResourceByOrigin(EnvoyResourceOriginBackendSync)) {
		// Check if any of the inputs have changed. If not we can skip processing it.
		ws, found := bs.watchSets[res.ClusterServiceName()]
		if found {
			if !ws.HasAny(closedWatches) {
				// None of the queries made when processing this service changed, so nothing to do.
				// Add in the prior watches to reprocess it later.
				allWatches.Merge(ws)
				continue
			}

			// Clear the old watches.
			ws.Clear()
		} else {
			// No watch set found, create one.
			ws = statedb.NewWatchSet()
			bs.watchSets[res.ClusterServiceName()] = ws
		}

		if len(res.ClusterReferences) == 0 {
			// No CEC references this cluster resource. We can delete it.
			bs.envoyResources.Delete(wtxn, res)
			delete(bs.watchSets, res.ClusterServiceName())
			continue
		}

		prevEndpoints := res.Resources.Endpoints
		var newEndpoints []*envoy_config_endpoint.ClusterLoadAssignment

		// Look up the referenced service for the port name to port number mappings.
		svc, _, watchSvc, found := bs.writer.Services().GetWatch(wtxn, loadbalancer.ServiceByName(res.ClusterServiceName()))
		ws.Add(watchSvc)
		if found {
			// Look up associated backends and update the load assignments.
			bes, watchBes := bs.writer.BackendsForService(wtxn, svc.Name)
			ws.Add(watchBes)
			newEndpoints = computeLoadAssignments(
				svc.Name,
				res.ClusterReferences,
				svc.PortNames,
				bs.writer.SelectBackends(bes, svc, nil))
		} else {
			// No service found (yet) and thus there are no endpoints.
			newEndpoints = nil
		}

		claEqual := func(a, b *envoy_config_endpoint.ClusterLoadAssignment) bool {
			return proto.Equal(a, b)
		}
		endpointsEqual := slices.EqualFunc(prevEndpoints, newEndpoints, claEqual)

		if !endpointsEqual || (res.Status.Kind != reconciler.StatusKindDone && res.Status.Kind != reconciler.StatusKindPending) {
			res = res.Clone()
			res.Status = reconciler.StatusPending()
			res.Resources.Endpoints = newEndpoints
			_, _, watchResource, _ := bs.envoyResources.InsertWatch(wtxn, res)
			ws.Add(watchResource)
		} else {
			// Endpoints did not change so no need to update it.
			_, _, watchResource, _ := bs.envoyResources.GetWatch(wtxn, EnvoyResourceByName(res.Name))
			ws.Add(watchResource)
		}

		allWatches.Merge(ws)
	}
}

func computeLoadAssignments(
	serviceName loadbalancer.ServiceName,
	clusterRefs clusterReferences,
	portNames map[string]uint16,
	backends iter.Seq2[loadbalancer.BackendParams, statedb.Revision],
) (assignments []*envoy_config_endpoint.ClusterLoadAssignment) {
	// Partition backends by port name.
	backendMap := map[string]map[string]loadbalancer.BackendParams{}

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
				backends = map[string]loadbalancer.BackendParams{}
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
