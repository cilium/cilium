// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	envoy_config_core "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_endpoint "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/part"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

var (
	experimentalCell = cell.Module(
		"experimental",
		"Integration to experimental LB control-plane",

		cell.ProvidePrivate(
			cecListerWatchers,
			newEnvoySyncer,
			newPolicyTrigger,
		),

		experimentalTableCells,
		experimentalControllerCells,
	)

	experimentalControllerCells = cell.Group(
		cell.Provide(
			newCECController,
		),
		cell.Invoke((*cecController).setWriter),
	)

	experimentalTableCells = cell.Group(
		cell.ProvidePrivate(
			newCECTable,
			statedb.RWTable[*CEC].ToTable,
		),
		cell.Invoke(
			registerCECReflector,
		),
	)
)

type cecControllerParams struct {
	cell.In

	DB        *statedb.DB
	JobGroup  job.Group
	Log       *slog.Logger
	ExpConfig experimental.Config

	CECs          statedb.Table[*CEC]
	EnvoySyncer   envoySyncer
	PolicyTrigger policyTrigger
}

type envoySyncer interface {
	UpdateResources(ctx context.Context, old, new envoy.Resources)
	UpsertResources(context.Context, envoy.Resources)
	DeleteResources(context.Context, envoy.Resources)
}

type policyTrigger interface {
	TriggerPolicyUpdates()
}

type cecController struct {
	params cecControllerParams
	writer *experimental.Writer
}

type cecControllerOut struct {
	cell.Out

	C    *cecController
	Hook experimental.ServiceHook `group:"service-hooks"`
}

func newCECController(params cecControllerParams) cecControllerOut {
	if !params.ExpConfig.EnableExperimentalLB {
		return cecControllerOut{}
	}

	c := &cecController{params, nil}
	params.JobGroup.Add(job.OneShot("control-loop", c.loop))
	return cecControllerOut{
		C:    c,
		Hook: c.onServiceUpsert,
	}
}

func (c *cecController) setWriter(w *experimental.Writer) {
	if c != nil {
		c.writer = w
	}
}

func (c *cecController) loop(ctx context.Context, health cell.Health) error {
	var (
		// Services table is used for looking up the service on which we're
		// setting the proxy redirection.
		svcs statedb.Table[*experimental.Service] = c.writer.Services()

		// Iterator for changes (upsert/delete) to the cilium envoy config table.
		// We process each change and look up a referenced service to set/unset the
		// proxy redirection.
		changes statedb.ChangeIterator[*CEC]

		backends statedb.ChangeIterator[*experimental.Backend]

		// servicesToSync is the set of service names for which we sync backends to Envoy.
		servicesToSync = sets.New[loadbalancer.ServiceName]()

		// allocatedPorts is the set of listener ports that have been allocated.
		// Used to gauge for the need for a policy recomputation for the case
		// when the CEC is processed late.
		allocatedPorts = part.Set[uint16]{}

		// Rate limiter to process changes in larger batches and to avoid processing
		// intermediate object states.
		limiter = rate.NewLimiter(50*time.Millisecond, 1)

		prevResources = map[k8sTypes.NamespacedName]envoy.Resources{}
	)

	{
		wtxn := c.params.DB.WriteTxn(c.params.CECs, c.writer.Backends())
		var err error
		changes, err = c.params.CECs.Changes(wtxn)
		if err == nil {
			backends, err = c.writer.Backends().Changes(wtxn)
		}
		wtxn.Commit()
		if err != nil {
			return err
		}
	}

	for {
		// Rate limit to do larger transactions and to avoid processing intermediate
		// states.
		if err := limiter.Wait(ctx); err != nil {
			return err
		}

		// Wait for new changes
		rtxn := c.params.DB.ReadTxn()
		select {
		case <-ctx.Done():
			return nil
		case <-changes.Watch(rtxn):
		case <-backends.Watch(rtxn):
		}

		// The set of services for which to resync backends.
		resync := sets.New[loadbalancer.ServiceName]()
		toUpdate := map[k8sTypes.NamespacedName]*envoy.Resources{}

		prevAllocatedPorts := allocatedPorts

		// Process the changed CECs and set the proxy ports of referenced services.
		// With the WriteTxn held we should do nothing more than update services and
		// collect what we need to sync towards Envoy.
		wtxn := c.writer.WriteTxn()
		for change, _, ok := changes.Next(); ok; change, _, ok = changes.Next() {
			cec := change.Object

			// Services that need to be redirected to Envoy and which need backend syncing.
			for _, svcl := range cec.Spec.Services {
				name := loadbalancer.ServiceName{
					Namespace: svcl.Namespace,
					Name:      svcl.Name,
				}

				if change.Deleted {
					servicesToSync.Delete(name)
				} else {
					servicesToSync.Insert(name)
					resync.Insert(name)
				}

				svc, _, found := svcs.Get(wtxn, experimental.ServiceByName(name))
				if found {
					// Do an upsert to trigger onServiceUpsert() to fill in the L7ProxyPort.
					c.writer.UpsertService(wtxn, svc.Clone())
				}
			}

			// Services that only need backend syncing.
			for _, beSvc := range cec.Spec.BackendServices {
				// FIXME: beSvc.Ports.

				name := loadbalancer.ServiceName{
					Namespace: beSvc.Namespace,
					Name:      beSvc.Name,
				}
				if change.Deleted {
					servicesToSync.Delete(name)
				} else {
					servicesToSync.Insert(name)
					resync.Insert(name)
				}
			}

			for _, l := range cec.Resources.Listeners {
				if addr := l.GetAddress(); addr != nil {
					if sa := addr.GetSocketAddress(); sa != nil {
						proxyPort := uint16(sa.GetPortValue())
						if change.Deleted {
							allocatedPorts = allocatedPorts.Delete(proxyPort)
						} else {
							allocatedPorts = allocatedPorts.Set(proxyPort)
						}
					}
				}
			}

			if change.Deleted {
				toUpdate[cec.Name] = nil
			} else {
				toUpdate[cec.Name] = &cec.Resources
			}
		}
		rtxn = wtxn.Commit()

		// Iterate over changed backends to collect services that need a resync
		for change, _, ok := backends.Next(); ok; change, _, ok = backends.Next() {
			iter := change.Object.Instances.All()
			for name, _, ok := iter.Next(); ok; name, _, ok = iter.Next() {
				if servicesToSync.Has(name) {
					resync.Insert(name)
				}
			}
		}

		// Update Envoy with the new resources.
		// TODO: If we so choose, we could do the envoy syncing before updating the load-balancing state.
		for name, res := range toUpdate {
			if res == nil {
				c.params.EnvoySyncer.DeleteResources(ctx, prevResources[name])
				delete(prevResources, name)
			} else {
				r := *res
				c.params.EnvoySyncer.UpdateResources(ctx, prevResources[name], r)
				prevResources[name] = r
			}
		}

		// Synchronize backends to Envoy
		// TODO: Can we merge this with the above?
		for name := range resync {
			// TODO: Keep track of the previous set to avoid unnecessary work changes.
			bes := statedb.Collect(
				c.writer.Backends().List(rtxn, experimental.BackendByServiceName(name)),
			)
			c.params.EnvoySyncer.UpsertResources(ctx, envoy.Resources{
				Endpoints: backendsToLoadAssignments(name, bes),
			})
		}

		// Retrigger policy computation if the allocated proxy ports have changed.
		// This is needed when the CEC is processed after the policies have been
		// computed.
		if !allocatedPorts.Equal(prevAllocatedPorts) {
			c.params.PolicyTrigger.TriggerPolicyUpdates()
		}
	}
}

func lookupProxyPort(cec *CEC, svcl *ciliumv2.ServiceListener) uint16 {
	if svcl.Listener != "" {
		// Listener names are qualified after parsing, so qualify the listener reference as well for it to match
		svcListener, _ := api.ResourceQualifiedName(
			cec.Name.Namespace, cec.Name.Name, svcl.Listener, api.ForceNamespace)
		port, _ := cec.Listeners.Get(svcListener)
		return port
	}

	iter := cec.Listeners.All()
	if _, port, ok := iter.Next(); ok {
		return port
	}
	return 0
}

// onServiceUpsert is called when the service is upserted, but before it is commited.
// We set the proxy port on the service if there's a matching CEC.
func (c *cecController) onServiceUpsert(txn statedb.ReadTxn, svc *experimental.Service) {
	c.params.Log.Info("onServiceUpsert", "name", svc.Name)

	// Look up if there is a CiliumEnvoyConfig that references this service.
	cec, _, found := c.params.CECs.Get(txn, cecByServiceName(svc.Name))
	if !found {
		c.params.Log.Info("onServiceUpsert: CEC not found", "name", svc.Name)
		svc.ProxyRedirect = nil
		return
	}

	// Find the service listener that referenced this service.
	var svcl *ciliumv2.ServiceListener
	for _, l := range cec.Spec.Services {
		if l.Namespace == svc.Name.Namespace && l.Name == svc.Name.Name {
			svcl = l
			break
		}
	}
	if svcl == nil {
		panic("BUG: Table index pointed to a CEC for a service listener, but it was not there.")
	}

	proxyPort := lookupProxyPort(cec, svcl)
	c.params.Log.Debug("Setting proxy redirection (on service upsert)",
		"namespace", svcl.Namespace,
		"name", svcl.Name,
		"proxyPort", proxyPort,
		"listener", svcl.Listener)
	if proxyPort == 0 {
		svc.ProxyRedirect = nil
	} else {
		svc.ProxyRedirect = &experimental.ProxyRedirect{
			ProxyPort: proxyPort,
			Ports:     svcl.Ports,
		}
	}

	return
}

func backendsToLoadAssignments(serviceName loadbalancer.ServiceName, backends []*experimental.Backend) []*envoy_config_endpoint.ClusterLoadAssignment {
	var endpoints []*envoy_config_endpoint.ClusterLoadAssignment

	// Partition backends by port name.
	backendMap := map[string][]*experimental.Backend{}
	for _, be := range backends {
		_, found := be.Instances.Get(serviceName)
		if !found {
			continue
		}
		// FIXME: support filtering by port name if [cilium_v2.Service.Ports] is a
		// port name not number.
		//backendMap[inst.PortName] = append(backendMap[inst.PortName], be)

		backendMap[anyPort] = append(backendMap[anyPort], be)
	}

	for port, bes := range backendMap {
		var lbEndpoints []*envoy_config_endpoint.LbEndpoint
		for _, be := range bes {
			if be.Protocol != loadbalancer.TCP {
				// Only TCP services supported with Envoy for now
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
		endpoints = append(endpoints, endpoint)

		// for backward compatibility, if any port is allowed, publish one more
		// endpoint having cluster name as service name.
		if port == anyPort {
			endpoints = append(endpoints, &envoy_config_endpoint.ClusterLoadAssignment{
				ClusterName: serviceName.String(),
				Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{
					{
						LbEndpoints: lbEndpoints,
					},
				},
			})
		}
	}

	return endpoints
}

type policyTriggerWrapper struct{ updater *policy.Updater }

func (p policyTriggerWrapper) TriggerPolicyUpdates() {
	p.updater.TriggerPolicyUpdates(true, "Envoy Listeners changed")
}

func newPolicyTrigger(log *slog.Logger, updater *policy.Updater) policyTrigger {
	return policyTriggerWrapper{updater}
}

// TODO: Alternatively we have a reconciler against Table[*cec] that deals with
// reconciling towards Envoy. That is if we need the retry handling here. The
// current implementation pushes the resources to a cache and then waits for
// completion, so it might not make sense to have retry handling at this level.
type envoySyncerWrapper struct {
	log *slog.Logger
	xds envoy.XDSServer
}

// DeleteResources implements envoySyncer.
func (e *envoySyncerWrapper) DeleteResources(ctx context.Context, res envoy.Resources) {
	err := e.xds.DeleteEnvoyResources(ctx, res)
	if err != nil {
		// FIXME proper handling
		e.log.Error("DeleteEnvoyResources", logfields.Error, err)
	}
}

// UpdateResources implements envoySyncer.
func (e *envoySyncerWrapper) UpdateResources(ctx context.Context, old envoy.Resources, new envoy.Resources) {
	err := e.xds.UpdateEnvoyResources(ctx, old, new)
	if err != nil {
		// FIXME proper handling
		e.log.Error("UpdateEnvoyResources", logfields.Error, err)

		// TODO: [old] gets updated to [new] regardless of errors. Likely not correct.
	}
}

// UpsertResources implements envoySyncer.
func (e *envoySyncerWrapper) UpsertResources(ctx context.Context, res envoy.Resources) {
	err := e.xds.UpsertEnvoyResources(ctx, res)
	if err != nil {
		// FIXME proper handling
		e.log.Error("UpsertEnvoyResources", logfields.Error, err)
	}
}

var _ envoySyncer = &envoySyncerWrapper{}

func newEnvoySyncer(log *slog.Logger, xds envoy.XDSServer) envoySyncer {
	return &envoySyncerWrapper{log, xds}
}
