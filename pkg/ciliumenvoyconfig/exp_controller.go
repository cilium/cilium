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
	"github.com/cilium/statedb/part"
	"github.com/cilium/statedb/reconciler"
	"github.com/cilium/stream"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy"
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

	NodeLabels    *nodeLabels
	CECs          statedb.RWTable[*CEC]
	EnvoySyncer   resourceMutator
	PolicyTrigger policyTrigger
}

type resourceMutator interface {
	DeleteEnvoyResources(context.Context, envoy.Resources) error
	UpdateEnvoyResources(context.Context, envoy.Resources, envoy.Resources) error
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

func newNodeLabels() *nodeLabels {
	nl := &nodeLabels{}
	lbls := map[string]string{}
	nl.Store(&lbls)
	return nl
}

func newCECController(params cecControllerParams) cecControllerOut {
	if !params.ExpConfig.EnableExperimentalLB {
		return cecControllerOut{}
	}

	c := &cecController{params, nil}
	params.JobGroup.Add(job.OneShot("proxy-redirect-controller", c.proxyRedirectController))
	params.JobGroup.Add(job.OneShot("backends-controller", c.backendController))
	params.JobGroup.Add(job.OneShot("node-label-controller", c.nodeLabelController))
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

// proxyRedirectController watches for changed CECs and updates the proxy redirect in services.
func (c *cecController) proxyRedirectController(ctx context.Context, health cell.Health) error {
	wtxn := c.params.DB.WriteTxn(c.params.CECs)
	changeIter, err := c.params.CECs.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return err
	}

	svcs := c.writer.Services()
	limiter := rate.NewLimiter(50*time.Millisecond, 3)
	listeners := part.Set[uint16]{}

	for {
		wtxn := c.writer.WriteTxn()
		changes, watch := changeIter.Next(wtxn)
		oldListeners := listeners
		for change := range changes {
			cec := change.Object
			if !change.Deleted && cec.Status.Kind != reconciler.StatusKindDone {
				// Only process the CEC once it has been reconciled towards Envoy to avoid
				// setting redirects before Envoy is ready.
				continue
			}

			for _, port := range cec.Listeners.All() {
				if change.Deleted {
					listeners = listeners.Delete(port)
				} else {
					listeners = listeners.Set(port)
				}
			}

			for _, svcl := range cec.Spec.Services {
				svc, _, found := svcs.Get(wtxn, experimental.ServiceByName(svcl.ServiceName()))
				if found && (change.Deleted || !getProxyRedirect(cec, svcl).Equal(svc.ProxyRedirect)) {
					// Do an upsert to call into onServiceUpsert() to update the L7ProxyPort.
					c.writer.UpsertService(wtxn, svc.Clone())
				}
			}
		}
		wtxn.Commit()

		// When listeners change trigger the policy updates.
		if !oldListeners.Equal(listeners) {
			// TODO: Policy does not need to be recomputed for this, but if we do not 'force'
			// the bpf maps are not updated with the new proxy ports either. Move from the
			// simple boolean to an enum that can more selectively skip regeneration steps (like
			// we do for the datapath recompilations already?)
			c.params.PolicyTrigger.TriggerPolicyUpdates()
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}

		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}
}

// backendController watches the frontends (that are associated with backends) for changes
// and recomputes the endpoints resource. Frontends are watched as the services in CiliumEnvoyConfig
// can specify frontend ports to filter by.
func (c *cecController) backendController(ctx context.Context, health cell.Health) error {
	frontends := c.writer.Frontends()
	wtxn := c.params.DB.WriteTxn(frontends)
	changeIter, err := c.writer.Frontends().Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return err
	}

	limiter := rate.NewLimiter(50*time.Millisecond, 3)

	for {
		// Iterate over the changes to collect the services that reference changed backends.
		wtxn := c.params.DB.WriteTxn(c.params.CECs)
		services := sets.New[loadbalancer.ServiceName]()
		changes, watch := changeIter.Next(wtxn)
		for change := range changes {
			services.Insert(change.Object.ServiceName)
		}

		// Find all CECs that reference those services and recompute their backends.
		visited := sets.New[CECName]()
		for serviceName := range services {
			for cec := range c.params.CECs.List(wtxn, CECByServiceName(serviceName)) {
				if visited.Has(cec.Name) {
					continue
				}
				visited.Insert(cec.Name)
				cec = cec.Clone()
				if updateBackends(cec, wtxn, frontends) {
					c.params.CECs.Insert(wtxn, cec)
				}
			}
		}
		wtxn.Commit()

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}

		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}
}

// nodeLabelController updates the [SelectsLocalNode] when node labels change.
func (c *cecController) nodeLabelController(ctx context.Context, health cell.Health) error {
	localNodeChanges := stream.ToChannel(ctx, c.params.LocalNodeStore)

	for localNode := range localNodeChanges {
		newLabels := localNode.Labels
		oldLabels := *c.params.NodeLabels.Load()

		if !maps.Equal(newLabels, oldLabels) {
			c.params.Log.Debug("Labels changed", "old", oldLabels, "new", newLabels)

			// Since the labels changed, recompute 'SelectsLocalNode'
			// for all CECs.
			wtxn := c.params.DB.WriteTxn(c.params.CECs)

			// Store the new labels so the reflector can compute 'SelectsLocalNode'
			// on the fly. The reflector may already update 'SelectsLocalNode' to the
			// correct value, so the recomputation that follows may be duplicate for
			// some CECs, but that's fine. This is updated with the CEC table lock held
			// and read by CEC reflector with the table lock which ensures consistency.
			// With the Table[Node] changes in https://github.com/cilium/cilium/pull/32144
			// this can be removed and we can instead read the labels directly from the node
			// table.
			labelSet := labels.Set(newLabels)
			c.params.NodeLabels.Store(&newLabels)

			for cec := range c.params.CECs.All(wtxn) {
				if cec.Selector != nil {
					selects := cec.Selector.Matches(labelSet)
					if selects != cec.SelectsLocalNode {
						cec = cec.Clone()
						cec.SelectsLocalNode = selects
						cec.Status = reconciler.StatusPending()
						c.params.CECs.Insert(wtxn, cec)
					}
				}
			}
			wtxn.Commit()
		}
	}
	return nil
}

// updateBackends recomputes the endpoint resources. Returns true if updated.
func updateBackends(cec *CEC, txn statedb.ReadTxn, fes statedb.Table[*experimental.Frontend]) bool {
	revision := fes.Revision(txn)
	if cec.FrontendsRevision > revision {
		// Already computed with a newer revision. This is used to coordinate between
		// the reflector and the backend controller.
		return false
	}
	cec.FrontendsRevision = revision

	services := map[loadbalancer.ServiceName]sets.Set[string]{}
	for _, l := range cec.Spec.Services {
		name := l.ServiceName()
		ports := services[name]
		if ports == nil {
			ports = sets.New[string]()
			services[name] = ports
		}
		for _, p := range l.Ports {
			ports.Insert(strconv.Itoa(int(p)))
		}
	}
	for _, l := range cec.Spec.BackendServices {
		name := l.ServiceName()
		ports := services[name]
		if ports == nil {
			ports = sets.New[string]()
			services[name] = ports
		}
		for _, p := range l.Ports {
			ports.Insert(p)
		}
	}
	assignments := []*envoy_config_endpoint.ClusterLoadAssignment{}
	for svc, ports := range services {
		assignments = append(
			assignments,
			backendsToLoadAssignments(
				svc,
				ports,
				fes.List(txn, experimental.FrontendByServiceName(svc)))...)
	}
	if assignmentsEqual(cec.Resources.Endpoints, assignments) {
		return false
	}
	cec.Resources.Endpoints = assignments
	cec.Status = reconciler.StatusPending()
	return true
}

func backendsToLoadAssignments(
	serviceName loadbalancer.ServiceName,
	ports sets.Set[string],
	frontends iter.Seq2[*experimental.Frontend, statedb.Revision]) []*envoy_config_endpoint.ClusterLoadAssignment {
	var endpoints []*envoy_config_endpoint.ClusterLoadAssignment

	// Partition backends by port name.
	backendMap := map[string]map[string]*experimental.Backend{}
	backendMap[anyPort] = nil
	for fe := range frontends {
		portName := anyPort
		// If ports are specified, only pick frontends with matching port or port name.
		if ports.Len() > 0 {
			switch {
			case ports.Has(string(fe.PortName)):
				portName = string(fe.PortName)
			case ports.Has(strconv.Itoa(int(fe.Address.Port))):
				portName = strconv.Itoa(int(fe.Address.Port))
			case ports.Has(strconv.Itoa(int(fe.ServicePort))):
				portName = strconv.Itoa(int(fe.ServicePort))
			default:
				continue
			}
		}
		for _, beWithRev := range fe.Backends {
			be := beWithRev.Backend
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

// assignmentsEqual returns false if the cluster load assignments are not equal. Equal assignments but in different
// order are assumed non-equal.
func assignmentsEqual(a []*envoy_config_endpoint.ClusterLoadAssignment, b []*envoy_config_endpoint.ClusterLoadAssignment) bool {

	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !proto.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
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

// onServiceUpsert is called when the service is upserted, but before it is committed.
// We set the proxy port on the service if there's a matching CEC.
func (c *cecController) onServiceUpsert(txn statedb.ReadTxn, svc *experimental.Service) {
	// Look up if there is a CiliumEnvoyConfig that references this service.
	cec, _, found := c.params.CECs.Get(txn, CECByServiceName(svc.Name))
	if !found {
		c.params.Log.Debug("onServiceUpsert: CEC not found", "name", svc.Name)
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
		return
	}

	pr := getProxyRedirect(cec, svcl)
	c.params.Log.Debug("Setting proxy redirection (on service upsert)",
		"namespace", svcl.Namespace,
		"name", svcl.Name,
		"ProxyRedirect", pr,
		"Listener", svcl.Listener)
	svc.ProxyRedirect = pr
}

type policyTriggerWrapper struct{ updater *policy.Updater }

func (p policyTriggerWrapper) TriggerPolicyUpdates() {
	p.updater.TriggerPolicyUpdates("Envoy Listeners changed")
}

func newPolicyTrigger(log *slog.Logger, updater *policy.Updater) policyTrigger {
	return policyTriggerWrapper{updater}
}

type envoyOps struct {
	log *slog.Logger
	xds resourceMutator
}

// Delete implements reconciler.Operations.
func (ops *envoyOps) Delete(ctx context.Context, _ statedb.ReadTxn, _ statedb.Revision, cec *CEC) error {
	if prev := cec.ReconciledResources; prev != nil {
		// Perform the deletion with the resources that were last successfully reconciled
		// instead of whatever the latest one is (which would have not been pushed to Envoy).
		return ops.xds.DeleteEnvoyResources(ctx, *prev)
	}
	return nil
}

// Prune implements reconciler.Operations.
func (ops *envoyOps) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[*CEC, statedb.Revision]) error {
	return nil
}

// Update implements reconciler.Operations.
func (ops *envoyOps) Update(ctx context.Context, txn statedb.ReadTxn, _ statedb.Revision, cec *CEC) error {
	var prevResources envoy.Resources
	if cec.ReconciledResources != nil {
		prevResources = *cec.ReconciledResources
	}

	var err error
	if cec.SelectsLocalNode {
		resources := cec.Resources
		err := ops.xds.UpdateEnvoyResources(ctx, prevResources, resources)
		if err == nil {
			cec.ReconciledResources = &resources
		}
	} else if cec.ReconciledResources != nil {
		// The local node no longer selected and it had been reconciled to envoy previously.
		// Delete the resources and forget.
		err = ops.xds.DeleteEnvoyResources(ctx, prevResources)
		if err == nil {
			cec.ReconciledResources = nil
		}
	}
	return err
}

var _ reconciler.Operations[*CEC] = &envoyOps{}

func registerEnvoyReconciler(log *slog.Logger, xds resourceMutator, params reconciler.Params, cecs statedb.RWTable[*CEC]) error {
	ops := &envoyOps{
		log: log, xds: xds,
	}
	_, err := reconciler.Register(
		params,
		cecs,
		(*CEC).Clone,
		(*CEC).SetStatus,
		(*CEC).GetStatus,
		ops,
		nil,
		reconciler.WithoutPruning(),
	)
	return err
}
