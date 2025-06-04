// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package writer

import (
	"context"
	"fmt"
	"io"
	"iter"
	"slices"
	"strings"
	"sync/atomic"
	"text/tabwriter"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/part"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// Writer provides validated write access to the service load-balancing state.
type Writer struct {
	nodeName string
	nodeZone atomic.Pointer[string]

	db        *statedb.DB
	nodeAddrs statedb.Table[tables.NodeAddress]
	svcs      statedb.RWTable[*loadbalancer.Service]
	fes       statedb.RWTable[*loadbalancer.Frontend]
	bes       statedb.RWTable[*loadbalancer.Backend]
	lns       *node.LocalNodeStore

	svcHooks         []ServiceHook
	sourcePriorities map[source.Source]uint8 // The smaller the int, the more preferred the source. Use via sourcePriority().

	selectBackendsFunc SelectBackendsFunc

	extCfg *loadbalancer.ExternalConfig
}

type SelectBackendsFunc = func(iter.Seq2[loadbalancer.BackendParams, statedb.Revision], *loadbalancer.Service, *loadbalancer.Frontend) iter.Seq2[loadbalancer.BackendParams, statedb.Revision]

// Backends for the local cluster are associated with ID 0, regardless of the real cluster id.
const LocalClusterID = 0

type writerParams struct {
	cell.In

	Config         loadbalancer.Config
	DB             *statedb.DB
	NodeAddresses  statedb.Table[tables.NodeAddress]
	Services       statedb.RWTable[*loadbalancer.Service]
	Frontends      statedb.RWTable[*loadbalancer.Frontend]
	Backends       statedb.RWTable[*loadbalancer.Backend]
	LocalNodeStore *node.LocalNodeStore

	ServiceHooks []ServiceHook `group:"service-hooks"`

	SourcePriorities source.Sources

	ExtCfg loadbalancer.ExternalConfig
}

func init() {
	part.RegisterKeyType(loadbalancer.BackendInstanceKey.Key)
}

func NewWriter(p writerParams) (*Writer, error) {
	if !p.Config.EnableExperimentalLB {
		return nil, nil
	}
	w := &Writer{
		nodeName:         nodeTypes.GetName(),
		db:               p.DB,
		bes:              p.Backends,
		fes:              p.Frontends,
		svcs:             p.Services,
		lns:              p.LocalNodeStore,
		nodeAddrs:        p.NodeAddresses,
		svcHooks:         p.ServiceHooks,
		sourcePriorities: priorityMapFromSlice(p.SourcePriorities),
		extCfg:           &p.ExtCfg,
	}
	w.selectBackendsFunc = w.DefaultSelectBackends
	return w, nil
}

func (w *Writer) SetSelectBackendsFunc(fn SelectBackendsFunc) {
	w.selectBackendsFunc = fn
}

// SelectBackends filters backends associated with [svc]. If [optionalFrontend] is non-nil, then backends are further filtered
// by frontend IP family, protocol and port name.
func (w *Writer) SelectBackends(bes iter.Seq2[loadbalancer.BackendParams, statedb.Revision], svc *loadbalancer.Service, optionalFrontend *loadbalancer.Frontend) iter.Seq2[loadbalancer.BackendParams, statedb.Revision] {
	return w.selectBackendsFunc(bes, svc, optionalFrontend)
}

// BackendsForService returns all backends associated with a given service without any filtering.
func (w *Writer) BackendsForService(txn statedb.ReadTxn, svc loadbalancer.ServiceName) (iter.Seq2[loadbalancer.BackendParams, statedb.Revision], <-chan struct{}) {
	bes, watch := w.bes.ListWatch(txn, loadbalancer.BackendByServiceName(svc))
	return statedb.Map(bes, func(be *loadbalancer.Backend) loadbalancer.BackendParams { return *be.GetInstance(svc) }), watch
}

func priorityMapFromSlice(s source.Sources) map[source.Source]uint8 {
	ans := make(map[source.Source]uint8)
	for i, src := range s {
		ans[src] = uint8(i)
	}
	return ans
}

func (w *Writer) sourcePriority(s source.Source) uint8 {
	p, ok := w.sourcePriorities[s]
	if !ok {
		return uint8(len(w.sourcePriorities))
	}
	return p
}

func (w *Writer) IsEnabled() bool {
	return w != nil
}

// RegisterInitializer registers a component as an initializer to the load-balancing
// tables. This blocks pruning of data until this and all other registered initializers
// have called the returned 'complete' function.
func (w *Writer) RegisterInitializer(name string) (complete func(WriteTxn)) {
	txn := w.WriteTxn()
	compFE := w.fes.RegisterInitializer(txn, name)
	compBE := w.bes.RegisterInitializer(txn, name)
	compSVC := w.svcs.RegisterInitializer(txn, name)
	txn.Commit()
	return func(wtxn WriteTxn) {
		compFE(wtxn.WriteTxn)
		compBE(wtxn.WriteTxn)
		compSVC(wtxn.WriteTxn)
	}
}

// Services returns the service table for reading.
// Convenience method for reducing dependencies.
func (w *Writer) Services() statedb.Table[*loadbalancer.Service] {
	return w.svcs
}

// Frontends returns the frontend table for reading.
// Convenience method for reducing dependencies.
func (w *Writer) Frontends() statedb.Table[*loadbalancer.Frontend] {
	return w.fes
}

// Backends returns the backend table for reading.
// Convenience method for reducing dependencies.
func (w *Writer) Backends() statedb.Table[*loadbalancer.Backend] {
	return w.bes
}

// ReadTxn returns a StateDB read transaction. Convenience method to
// be used with the above table getters.
func (w *Writer) ReadTxn() statedb.ReadTxn {
	return w.db.ReadTxn()
}

type WriteTxn struct {
	statedb.WriteTxn
}

// WriteTxn returns a write transaction against services & backends and other additional
// tables to be used with the methods of [Writer]. The returned transaction MUST be
// Abort()'ed or Commit()'ed.
func (w *Writer) WriteTxn(extraTables ...statedb.TableMeta) WriteTxn {
	return WriteTxn{
		w.db.WriteTxn(w.svcs, append(extraTables, w.bes, w.fes)...),
	}
}

func (w *Writer) updateZone(zone string) {
	// Grab a write transaction before updating [w.nodeZone]
	// to make sure there's no changes to the tables while we
	// refresh the frontends.
	txn := w.WriteTxn()
	defer txn.Abort()

	if zone == "" {
		w.nodeZone.Store(nil)
	} else {
		w.nodeZone.Store(&zone)
	}

	// Refresh all frontends associated with topology-aware services
	// as the backend selection might change.
	updated := false
	for fe := range w.fes.All(txn) {
		if fe.Service.TrafficDistribution == loadbalancer.TrafficDistributionPreferClose {
			fe = fe.Clone()
			w.refreshFrontend(txn, fe)
			w.fes.Insert(txn, fe)
			updated = true
		}
	}
	if updated {
		txn.Commit()
	}
}

func (w *Writer) UpsertService(txn WriteTxn, svc *loadbalancer.Service) (old *loadbalancer.Service, err error) {
	for _, hook := range w.svcHooks {
		hook(txn, svc)
	}
	old, _, err = w.svcs.Insert(txn, svc)
	if err == nil {
		err = w.updateServiceReferences(txn, svc)
	}
	return old, err
}

func (w *Writer) UpsertFrontend(txn WriteTxn, params loadbalancer.FrontendParams) (old *loadbalancer.Frontend, err error) {
	if err := w.validateFrontends(txn, params); err != nil {
		return nil, err
	}

	// Check if a frontend already exists that is associated to a different service.
	fe, _, found := w.fes.Get(txn, loadbalancer.FrontendByAddress(params.Address))
	if found && !fe.ServiceName.Equal(params.ServiceName) {
		return fe, fmt.Errorf("%w: %s is owned by %s", loadbalancer.ErrFrontendConflict, params.Address.StringWithProtocol(), fe.ServiceName)
	}

	// Lookup the service associated with the frontend. A frontend cannot be added
	// without the service already existing.
	svc, _, found := w.svcs.Get(txn, loadbalancer.ServiceByName(params.ServiceName))
	if !found {
		return nil, loadbalancer.ErrServiceNotFound
	}
	return w.upsertFrontendParams(txn, params, svc)
}

func (w *Writer) UpdateBackendHealth(txn WriteTxn, serviceName loadbalancer.ServiceName, backend loadbalancer.L3n4Addr, healthy bool) (bool, error) {
	be, _, ok := w.bes.Get(txn, loadbalancer.BackendByAddress(backend))
	if !ok {
		return false, loadbalancer.ErrServiceNotFound
	}
	inst := be.GetInstance(serviceName)
	if inst == nil {
		return false, loadbalancer.ErrServiceNotFound
	}
	if inst.Unhealthy == !healthy && !inst.UnhealthyUpdatedAt.IsZero() {
		return false, nil
	}

	be = be.Clone()
	inst.Unhealthy = !healthy
	inst.UnhealthyUpdatedAt = time.Now()
	be.Instances = be.Instances.Set(loadbalancer.BackendInstanceKey{ServiceName: serviceName, SourcePriority: w.sourcePriority(inst.Source)}, *inst)
	w.bes.Insert(txn, be)
	return true, w.RefreshFrontends(txn, serviceName)
}

func (w *Writer) upsertFrontendParams(txn WriteTxn, params loadbalancer.FrontendParams, svc *loadbalancer.Service) (old *loadbalancer.Frontend, err error) {
	if params.ServicePort == 0 {
		params.ServicePort = params.Address.Port
	}
	fe := &loadbalancer.Frontend{
		FrontendParams: params,
		Service:        svc,
	}
	var found bool
	if old, _, found = w.fes.Get(txn, loadbalancer.FrontendByAddress(params.Address)); found {
		fe.ID = old.ID
		fe.RedirectTo = old.RedirectTo
	}
	w.refreshFrontend(txn, fe)
	_, _, err = w.fes.Insert(txn, fe)
	return
}

// validateFrontends checks that the frontends being added are not already owned by other
// services.
func (w *Writer) validateFrontends(txn WriteTxn, fes ...loadbalancer.FrontendParams) error {
	// Validate that the frontends are not owned by other services.
	for _, params := range fes {
		fe, _, found := w.fes.Get(txn, loadbalancer.FrontendByAddress(params.Address))
		if found && !fe.ServiceName.Equal(params.ServiceName) {
			return fmt.Errorf("%w: %s is owned by %s", loadbalancer.ErrFrontendConflict, params.Address.StringWithProtocol(), fe.ServiceName)
		}
	}
	return nil
}

// UpsertServiceAndFrontends upserts the service and updates the set of associated frontends.
// Any frontends that do not exist in the new set are deleted.
func (w *Writer) UpsertServiceAndFrontends(txn WriteTxn, svc *loadbalancer.Service, fes ...loadbalancer.FrontendParams) error {
	if err := w.validateFrontends(txn, fes...); err != nil {
		return err
	}

	for _, hook := range w.svcHooks {
		hook(txn, svc)
	}
	_, _, err := w.svcs.Insert(txn, svc)
	if err != nil {
		return err
	}

	// Upsert the new frontends
	newAddrs := sets.New[loadbalancer.L3n4Addr]()
	for _, params := range fes {
		newAddrs.Insert(params.Address)
		params.ServiceName = svc.Name
		if _, err := w.upsertFrontendParams(txn, params, svc); err != nil {
			return err
		}
	}

	// Delete orphan frontends
	for fe := range w.fes.List(txn, loadbalancer.FrontendByServiceName(svc.Name)) {
		if newAddrs.Has(fe.Address) {
			continue
		}
		if _, _, err := w.fes.Delete(txn, fe); err != nil {
			return err
		}
	}

	return nil
}

func (w *Writer) updateServiceReferences(txn WriteTxn, svc *loadbalancer.Service) error {
	for fe := range w.fes.List(txn, loadbalancer.FrontendByServiceName(svc.Name)) {
		fe = fe.Clone()
		fe.Status = reconciler.StatusPending()
		fe.Service = svc
		if _, _, err := w.fes.Insert(txn, fe); err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) refreshFrontend(txn statedb.ReadTxn, fe *loadbalancer.Frontend) {
	fe.Status = reconciler.StatusPending()
	svc := fe.Service
	if fe.RedirectTo != nil {
		var found bool
		svc, _, found = w.svcs.Get(txn, loadbalancer.ServiceByName(*fe.RedirectTo))
		if !found {
			return
		}
	}
	bes, _ := w.BackendsForService(txn, svc.Name)
	fe.Backends = loadbalancer.BackendsSeq2(w.SelectBackends(bes, svc, fe))
}

func (w *Writer) RefreshFrontends(txn WriteTxn, name loadbalancer.ServiceName) error {
	for fe := range w.fes.List(txn, loadbalancer.FrontendByServiceName(name)) {
		fe = fe.Clone()
		w.refreshFrontend(txn, fe)
		if _, _, err := w.fes.Insert(txn, fe); err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) DefaultSelectBackends(bes iter.Seq2[loadbalancer.BackendParams, statedb.Revision], svc *loadbalancer.Service, fe *loadbalancer.Frontend) iter.Seq2[loadbalancer.BackendParams, statedb.Revision] {
	onlyLocal := false
	ipv4, ipv6 := true, true
	isLocalProxyDelegation := func(loadbalancer.L3n4Addr) bool { return true }
	if fe != nil {
		onlyLocal = shouldUseLocalBackends(w.extCfg, fe)
		if fe.Address.IsIPv6() {
			ipv4, ipv6 = false, true
		} else {
			ipv4, ipv6 = true, false
		}
	} else {
		onlyLocal = svc.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal

		// For proxy delegation we will consider backends that have a node IP as their
		// address as "local" when external traffic policy is set to local.
		if svc.GetProxyDelegation() != loadbalancer.SVCProxyDelegationNone {
			node, err := w.lns.Get(context.Background())
			if err == nil {
				isLocalProxyDelegation = func(addr loadbalancer.L3n4Addr) bool {
					return node.IsNodeIP(addr.AddrCluster.Addr()) != ""
				}
			}
		}
	}

	return func(yield func(loadbalancer.BackendParams, statedb.Revision) bool) {
		for be, rev := range bes {
			if fe != nil && fe.Address.Protocol != be.Address.Protocol {
				continue
			}
			if be.Address.IsIPv6() {
				if !ipv6 {
					continue
				}
			} else if !ipv4 {
				continue
			}
			if onlyLocal {
				if len(be.NodeName) != 0 && be.NodeName != w.nodeName {
					continue
				}
				if !isLocalProxyDelegation(be.Address) {
					continue
				}
			}
			if fe != nil {
				if fe.RedirectTo == nil && fe.Service.TrafficDistribution == loadbalancer.TrafficDistributionPreferClose {
					thisZone := w.nodeZone.Load()
					if len(be.ForZones) > 0 && thisZone != nil {
						// Topology-aware routing is enabled. Only use this backend if it is selected for this zone.
						if !slices.Contains(be.ForZones, *thisZone) {
							continue
						}
					}
				}
				if fe.PortName != "" {
					// A backend with specific port name requested. Look up what this backend
					// is called for this service.
					if !slices.Contains(be.PortNames, string(fe.PortName)) {
						continue
					}
				}
			}
			if !yield(be, rev) {
				return
			}
		}
	}
}

func (w *Writer) DeleteServiceAndFrontends(txn WriteTxn, name loadbalancer.ServiceName) error {
	svc, _, found := w.svcs.Get(txn, loadbalancer.ServiceByName(name))
	if !found {
		return statedb.ErrObjectNotFound
	}
	return w.deleteService(txn, svc)
}

func (w *Writer) deleteService(txn WriteTxn, svc *loadbalancer.Service) error {
	// Delete the frontends
	for fe := range w.fes.List(txn, loadbalancer.FrontendByServiceName(svc.Name)) {
		if _, _, err := w.fes.Delete(txn, fe); err != nil {
			return err
		}
	}

	// And finally delete the service itself.
	_, _, err := w.svcs.Delete(txn, svc)
	return err
}

// DeleteServicesBySource deletes all services from the specific source. This is used to
// implement "resynchronization", for example with K8s when the Watch() call fails and we need
// to start over with a List().
func (w *Writer) DeleteServicesBySource(txn WriteTxn, source source.Source) error {
	// Iterating over all as this is a rare operation and it would be costly
	// to always index by source.
	for svc := range w.svcs.All(txn) {
		if svc.Source == source {
			if err := w.deleteService(txn, svc); err != nil {
				return err
			}
		}
	}
	return nil
}

// DeletesBackendsBySource deletes all backends from the specific source.
func (w *Writer) DeleteBackendsBySource(txn WriteTxn, source source.Source) error {
	// Iterating over all as this is a rare operation and it would be costly
	// to always index by source.
	for be := range w.bes.All(txn) {
		for key, inst := range be.Instances.All() {
			if inst.Source == source {
				if err := w.removeBackendRef(txn, key.ServiceName, be); err != nil {
					return err
				}
				break
			}
		}
	}
	return nil
}

// UpsertBackends adds/updates backends for the given service.
func (w *Writer) UpsertBackends(txn WriteTxn, serviceName loadbalancer.ServiceName, source source.Source, bes ...loadbalancer.BackendParams) error {
	refs, err := w.updateBackends(txn, serviceName, source, LocalClusterID, bes)
	if err != nil {
		return err
	}

	for svc := range refs {
		if err := w.RefreshFrontends(txn, svc); err != nil {
			return err
		}
	}
	return nil
}

// SetBackends sets the backends associated with a service. Existing backends from this source that
// are associated with the service but are not given are released.
func (w *Writer) SetBackends(txn WriteTxn, name loadbalancer.ServiceName, source source.Source, bes ...loadbalancer.BackendParams) error {
	return w.SetBackendsOfCluster(txn, name, source, LocalClusterID, bes...)
}

// SetBackendsOfCluster sets the backends associated with a service from the specified cluster. It will
// not affect the backends from other clusters associated with the service.
func (w *Writer) SetBackendsOfCluster(txn WriteTxn, name loadbalancer.ServiceName, source source.Source, clusterID uint32, bes ...loadbalancer.BackendParams) error {
	addrs := sets.New[loadbalancer.L3n4Addr]()
	for _, be := range bes {
		addrs.Insert(be.Address)
	}

	orphans := statedb.Filter(
		w.bes.List(txn, loadbalancer.BackendByServiceName(name)),
		func(be *loadbalancer.Backend) bool {
			inst := be.GetInstanceFromSource(name, source)
			return inst != nil && inst.ClusterID == clusterID && !addrs.Has(be.Address)
		})

	refs, err := w.updateBackends(txn, name, source, clusterID, bes)
	if err != nil {
		return err
	}
	refs = refs.Insert(name) // Even for empty bes, we need to refresh this service.

	// Release orphaned backends, e.g. all backends from this source referencing this
	// service.
	for be := range orphans {
		if _, err := w.removeBackendRefPerSource(txn, name, be, source, clusterID); err != nil {
			return err
		}
	}

	// Recompute the backends associated with each frontend.
	for svc := range refs {
		if err := w.RefreshFrontends(txn, svc); err != nil {
			return err
		}
	}

	return nil
}

func (w *Writer) updateBackends(txn WriteTxn, serviceName loadbalancer.ServiceName, source source.Source, clusterID uint32, bes []loadbalancer.BackendParams) (sets.Set[loadbalancer.ServiceName], error) {
	// Collect all the service names linked with the updated backends in order to bump the
	// associated frontends for reconciliation.
	referencedServices := sets.New[loadbalancer.ServiceName]()

	for _, bep := range bes {
		var be loadbalancer.Backend
		be.Address = bep.Address

		if old, _, ok := w.bes.Get(txn, loadbalancer.BackendByAddress(bep.Address)); ok {
			be = *old
		}

		if inst := be.GetInstanceFromSource(serviceName, source); inst != nil {
			// Previous instance exists, keep the health information.
			bep.Unhealthy = inst.Unhealthy
			bep.UnhealthyUpdatedAt = inst.UnhealthyUpdatedAt
		}

		bep.Source = source
		bep.ClusterID = clusterID
		be.Instances = be.Instances.Set(
			loadbalancer.BackendInstanceKey{ServiceName: serviceName, SourcePriority: w.sourcePriority(bep.Source)},
			bep,
		)

		if _, _, err := w.bes.Insert(txn, &be); err != nil {
			return nil, err
		}

		for k := range be.PreferredInstances() {
			referencedServices.Insert(k.ServiceName)
		}
	}
	return referencedServices, nil
}

func (w *Writer) DeleteBackendsOfService(txn WriteTxn, name loadbalancer.ServiceName, src source.Source) error {
	return w.DeleteBackendsOfServiceFromCluster(txn, name, src, LocalClusterID)
}

func (w *Writer) DeleteBackendsOfServiceFromCluster(txn WriteTxn, name loadbalancer.ServiceName, src source.Source, clusterID uint32) error {
	for be := range w.bes.List(txn, loadbalancer.BackendByServiceName(name)) {
		if inst := be.GetInstanceFromSource(name, src); inst != nil {
			beNew, orphaned := backendReleasePerSource(be, name, src, clusterID)
			var err error
			if orphaned {
				_, _, err = w.bes.Delete(txn, beNew)
			} else if beNew != be {
				_, _, err = w.bes.Insert(txn, beNew)
			}
			if err != nil {
				return err
			}
		}
	}
	return w.RefreshFrontends(txn, name)
}

func (w *Writer) removeBackendRef(txn WriteTxn, name loadbalancer.ServiceName, be *loadbalancer.Backend) (err error) {
	be, orphan := backendRelease(be, name)
	if orphan {
		_, _, err = w.bes.Delete(txn, be)
	} else {
		_, _, err = w.bes.Insert(txn, be)
	}
	return err
}

func (w *Writer) removeBackendRefPerSource(txn WriteTxn, name loadbalancer.ServiceName, be *loadbalancer.Backend, src source.Source, clusterID uint32) (backend *loadbalancer.Backend, err error) {
	be, orphan := backendReleasePerSource(be, name, src, clusterID)
	if orphan {
		_, _, err = w.bes.Delete(txn, be)
	} else {
		_, _, err = w.bes.Insert(txn, be)
	}
	return be, err
}

func (w *Writer) ReleaseBackends(txn WriteTxn, name loadbalancer.ServiceName, addrs ...loadbalancer.L3n4Addr) error {
	if len(addrs) == 0 {
		return nil
	}
	for _, addr := range addrs {
		be, _, ok := w.bes.Get(txn, loadbalancer.BackendByAddress(addr))
		if !ok {
			return statedb.ErrObjectNotFound
		}

		if err := w.removeBackendRef(txn, name, be); err != nil {
			return err
		}
	}
	return w.RefreshFrontends(txn, name)
}

func (w *Writer) SetRedirectTo(txn WriteTxn, fe *loadbalancer.Frontend, to *loadbalancer.ServiceName) {
	if to == nil && fe.RedirectTo == nil {
		return
	}

	if to != nil && fe.RedirectTo != nil && to.Equal(*fe.RedirectTo) {
		return
	}

	fe = fe.Clone()
	fe.RedirectTo = to
	w.refreshFrontend(txn, fe)
	w.fes.Insert(txn, fe)
}

func (w *Writer) DebugDump(txn statedb.ReadTxn, to io.Writer) {
	tw := tabwriter.NewWriter(to, 5, 0, 3, ' ', 0)

	fmt.Fprintln(tw, "--- Services ---")
	fmt.Fprintln(tw, strings.Join((*loadbalancer.Service)(nil).TableHeader(), "\t"))
	for svc := range w.svcs.All(txn) {
		fmt.Fprintln(tw, strings.Join(svc.TableRow(), "\t"))
	}

	fmt.Fprintln(tw, "\n--- Frontends ---")
	fmt.Fprintln(tw, strings.Join((*loadbalancer.Frontend)(nil).TableHeader(), "\t"))
	for fe := range w.fes.All(txn) {
		fmt.Fprintln(tw, strings.Join(fe.TableRow(), "\t"))
	}

	fmt.Fprintln(tw, "\n--- Backends ---")
	fmt.Fprintln(tw, strings.Join((*loadbalancer.Backend)(nil).TableHeader(), "\t"))
	for be := range w.bes.All(txn) {
		fmt.Fprintln(tw, strings.Join(be.TableRow(), "\t"))
	}

	tw.Flush()
}

func isExtLocal(fe *loadbalancer.Frontend) bool {
	switch fe.Type {
	case loadbalancer.SVCTypeNodePort, loadbalancer.SVCTypeLoadBalancer, loadbalancer.SVCTypeExternalIPs:
		return fe.Service.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal
	default:
		return false
	}
}

func isIntLocal(extCfg *loadbalancer.ExternalConfig, fe *loadbalancer.Frontend) bool {
	if !extCfg.EnableInternalTrafficPolicy {
		return false
	}

	switch fe.Type {
	case loadbalancer.SVCTypeClusterIP, loadbalancer.SVCTypeNodePort, loadbalancer.SVCTypeLoadBalancer, loadbalancer.SVCTypeExternalIPs:
		return fe.Service.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal
	default:
		return false
	}
}

func shouldUseLocalBackends(extCfg *loadbalancer.ExternalConfig, fe *loadbalancer.Frontend) bool {
	// When both traffic policies are Local, there is only the external scope, which
	// should contain node-local backends only. Checking isExtLocal is still enough.
	switch fe.Address.Scope {
	case loadbalancer.ScopeExternal:
		if fe.Type == loadbalancer.SVCTypeClusterIP {
			// ClusterIP doesn't support externalTrafficPolicy and has only the
			// external scope, which contains only node-local backends when
			// internalTrafficPolicy=Local.
			return isIntLocal(extCfg, fe)
		}
		return isExtLocal(fe)
	case loadbalancer.ScopeInternal:
		return isIntLocal(extCfg, fe)
	default:
		return false
	}
}

func backendRelease(be *loadbalancer.Backend, name loadbalancer.ServiceName) (*loadbalancer.Backend, bool) {
	instances := be.Instances
	for k := range be.GetInstancesOfService(name) {
		instances = instances.Delete(k)
	}
	beCopy := *be
	beCopy.Instances = instances
	return &beCopy, beCopy.Instances.Len() == 0
}

func backendReleasePerSource(be *loadbalancer.Backend, name loadbalancer.ServiceName, source source.Source, clusterID uint32) (*loadbalancer.Backend, bool) {
	var keyToDelete *loadbalancer.BackendInstanceKey
	for k, inst := range be.GetInstancesOfService(name) {
		if inst.Source == source && inst.ClusterID == clusterID {
			keyToDelete = &k
			break
		}
	}
	if keyToDelete == nil {
		return be, be.Instances.Len() == 0
	}
	beCopy := *be
	beCopy.Instances = beCopy.Instances.Delete(*keyToDelete)
	return &beCopy, beCopy.Instances.Len() == 0
}
