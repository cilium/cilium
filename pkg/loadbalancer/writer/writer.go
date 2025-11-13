// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package writer

import (
	"fmt"
	"io"
	"iter"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/part"
	"github.com/cilium/statedb/reconciler"
	corev1 "k8s.io/api/core/v1"
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
	config loadbalancer.Config

	nodeName string

	db        *statedb.DB
	nodeAddrs statedb.Table[tables.NodeAddress]
	svcs      statedb.RWTable[*loadbalancer.Service]
	fes       statedb.RWTable[*loadbalancer.Frontend]
	bes       statedb.RWTable[*loadbalancer.Backend]
	nodes     statedb.Table[*node.LocalNode]

	sourcePriorities map[source.Source]uint8 // The smaller the int, the more preferred the source. Use via sourcePriority().

	selectBackendsFunc         SelectBackendsFunc
	isServiceHealthCheckedFunc IsServiceHealthCheckedFunc
}

type SelectBackendsFunc = func(statedb.ReadTxn, iter.Seq2[loadbalancer.BackendParams, statedb.Revision], *loadbalancer.Service, *loadbalancer.Frontend) iter.Seq2[loadbalancer.BackendParams, statedb.Revision]

type IsServiceHealthCheckedFunc = func(*loadbalancer.Service) bool

// Backends for the local cluster are associated with ID 0, regardless of the real cluster id.
const LocalClusterID = 0

type writerParams struct {
	cell.In

	Config        loadbalancer.Config
	DB            *statedb.DB
	NodeAddresses statedb.Table[tables.NodeAddress]
	Services      statedb.RWTable[*loadbalancer.Service]
	Frontends     statedb.RWTable[*loadbalancer.Frontend]
	Backends      statedb.RWTable[*loadbalancer.Backend]
	Nodes         statedb.Table[*node.LocalNode]

	SourcePriorities source.Sources
}

func init() {
	part.RegisterKeyType(loadbalancer.BackendInstanceKey.Key)
}

func NewWriter(p writerParams) (*Writer, error) {
	w := &Writer{
		config:           p.Config,
		nodeName:         nodeTypes.GetName(),
		db:               p.DB,
		bes:              p.Backends,
		fes:              p.Frontends,
		svcs:             p.Services,
		nodes:            p.Nodes,
		nodeAddrs:        p.NodeAddresses,
		sourcePriorities: priorityMapFromSlice(p.SourcePriorities),
	}
	w.selectBackendsFunc = w.DefaultSelectBackends
	return w, nil
}

func (w *Writer) SetSelectBackendsFunc(fn SelectBackendsFunc) {
	w.selectBackendsFunc = fn
}

func (w *Writer) SetIsServiceHealthCheckedFunc(fn IsServiceHealthCheckedFunc) {
	w.isServiceHealthCheckedFunc = fn
}

// SelectBackends filters backends associated with [svc]. If [optionalFrontend] is non-nil, then backends are further filtered
// by frontend IP family, protocol and port name.
func (w *Writer) SelectBackends(txn statedb.ReadTxn, bes iter.Seq2[loadbalancer.BackendParams, statedb.Revision], svc *loadbalancer.Service, optionalFrontend *loadbalancer.Frontend) iter.Seq2[loadbalancer.BackendParams, statedb.Revision] {
	selectedBackends := w.selectBackendsFunc(txn, bes, svc, optionalFrontend)

	// return all selected backends for services that should not be health checked
	if w.isServiceHealthCheckedFunc == nil || !w.isServiceHealthCheckedFunc(svc) {
		return selectedBackends
	}

	return func(yield func(loadbalancer.BackendParams, statedb.Revision) bool) {
		for be, rev := range selectedBackends {

			// filter backends that haven't been health checked yet
			if be.State == loadbalancer.BackendStateActive && be.UnhealthyUpdatedAt == nil {
				continue
			}

			if !yield(be, rev) {
				return
			}
		}
	}
}

// SelectBackendsForHealthChecking filters backends associated with [svc]. If [optionalFrontend] is non-nil, then backends are further filtered
// by frontend IP family, protocol and port name.
func (w *Writer) SelectBackendsForHealthChecking(txn statedb.ReadTxn, bes iter.Seq2[loadbalancer.BackendParams, statedb.Revision], svc *loadbalancer.Service, optionalFrontend *loadbalancer.Frontend) iter.Seq2[loadbalancer.BackendParams, statedb.Revision] {
	return w.selectBackendsFunc(txn, bes, svc, optionalFrontend)
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
	if len(extraTables) == 0 {
		return WriteTxn{w.db.WriteTxn(w.svcs, w.bes, w.fes)}
	}
	return WriteTxn{
		w.db.WriteTxn(append(extraTables, w.svcs, w.bes, w.fes)...),
	}
}

func (w *Writer) UpsertService(txn WriteTxn, svc *loadbalancer.Service) (old *loadbalancer.Service, err error) {
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

func (w *Writer) DeleteFrontend(txn WriteTxn, addr loadbalancer.L3n4Addr) {
	fe, _, found := w.fes.Get(txn, loadbalancer.FrontendByAddress(addr))
	if found {
		w.fes.Delete(txn, fe)
	}
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
	if inst.Unhealthy == !healthy && inst.UnhealthyUpdatedAt != nil {
		return false, nil
	}

	be = be.Clone()
	inst.Unhealthy = !healthy
	now := time.Now()
	inst.UnhealthyUpdatedAt = &now
	be.Instances = be.Instances.Set(loadbalancer.BackendInstanceKey{ServiceName: serviceName, SourcePriority: w.sourcePriority(inst.Source)}, *inst)
	w.bes.Insert(txn, be)
	return true, w.RefreshFrontends(txn, serviceName)
}

func (w *Writer) upsertFrontendParams(txn WriteTxn, params loadbalancer.FrontendParams, svc *loadbalancer.Service) (old *loadbalancer.Frontend, err error) {
	if params.ServicePort == 0 {
		params.ServicePort = params.Address.Port()
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

	_, _, err := w.svcs.Insert(txn, svc)
	if err != nil {
		return err
	}

	// Take the next revision assigned to a frontend. We'll use this as watermark to
	// detect which frontends associated with the service were not updated and are
	// thus orphans that can be deleted.
	minFrontendRevision := w.fes.Revision(txn) + 1

	// Upsert the new frontends
	for _, params := range fes {
		params.ServiceName = svc.Name
		if _, err := w.upsertFrontendParams(txn, params, svc); err != nil {
			return err
		}
	}

	// Delete orphan frontends
	for fe, rev := range w.fes.List(txn, loadbalancer.FrontendByServiceName(svc.Name)) {
		if rev < minFrontendRevision {
			if _, _, err := w.fes.Delete(txn, fe); err != nil {
				return err
			}
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
	fe.Backends = loadbalancer.BackendsSeq2(w.SelectBackends(txn, bes, svc, fe))
	fe.HealthCheckBackends = loadbalancer.BackendsSeq2(w.SelectBackendsForHealthChecking(txn, bes, svc, fe))
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

func (w *Writer) DefaultSelectBackends(txn statedb.ReadTxn, bes iter.Seq2[loadbalancer.BackendParams, statedb.Revision], svc *loadbalancer.Service, fe *loadbalancer.Frontend) iter.Seq2[loadbalancer.BackendParams, statedb.Revision] {
	onlyLocal := false
	ipv4, ipv6 := true, true
	isLocalProxyDelegation := func(loadbalancer.L3n4Addr) bool { return true }
	if fe != nil {
		onlyLocal = shouldUseLocalBackends(fe)
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
			if node, _, found := w.nodes.Get(txn, node.LocalNodeQuery); found {
				isLocalProxyDelegation = func(addr loadbalancer.L3n4Addr) bool {
					return node.IsNodeIP(addr.Addr()) != ""
				}
			}
		}
	}

	// Check whether the [BackendParams.ForZones] hints should be consulted when
	// selecting a backend.
	checkZoneHints := false
	var thisZone *string
	if node, _, found := w.nodes.Get(txn, node.LocalNodeQuery); found {
		if zone := node.Labels[corev1.LabelTopologyZone]; zone != "" {
			thisZone = &zone
		}
	}
	if w.config.EnableServiceTopology &&
		thisZone != nil &&
		fe != nil && fe.RedirectTo == nil &&
		fe.Service.TrafficDistribution == loadbalancer.TrafficDistributionPreferClose {
		// Topology-aware routing enabled. See if we can find any backends fitting
		// for our zone. If we don't find any we fall back to default behaviour.
		// https://kubernetes.io/docs/concepts/services-networking/topology-aware-routing/#safeguards
		candidatesFound, missingHints := false, false
		for be := range bes {
			if be.Zone != nil && len(be.Zone.ForZones) > 0 {
				if !candidatesFound && slices.Contains(be.Zone.ForZones, *thisZone) {
					candidatesFound = true
				}
			} else {
				missingHints = true
				break
			}
		}
		checkZoneHints = candidatesFound && !missingHints
	}

	return func(yield func(loadbalancer.BackendParams, statedb.Revision) bool) {
		// NOTE: [txn] is no longer valid here. Use it outside this closure.

		for be, rev := range bes {
			if fe != nil && fe.Address.Protocol() != be.Address.Protocol() {
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
			if checkZoneHints && !slices.Contains(be.Zone.ForZones, *thisZone) {
				continue
			}
			if fe != nil {
				if fe.PortName != "" && len(be.PortNames) > 0 {
					// A backend with specific port name requested. Look up what this backend
					// is called for this service when the backend has multiple (named) ports.
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

func (w *Writer) DeleteServiceAndFrontends(txn WriteTxn, name loadbalancer.ServiceName) (*loadbalancer.Service, error) {
	svc, _, found := w.svcs.Get(txn, loadbalancer.ServiceByName(name))
	if !found {
		return nil, statedb.ErrObjectNotFound
	}
	return svc, w.deleteService(txn, svc)
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
func (w *Writer) UpsertBackends(txn WriteTxn, serviceName loadbalancer.ServiceName, source source.Source, bes iter.Seq[loadbalancer.BackendParams]) error {
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

func (w *Writer) UpsertAndReleaseBackends(txn WriteTxn, serviceName loadbalancer.ServiceName, source source.Source, new iter.Seq[loadbalancer.BackendParams], orphans iter.Seq[loadbalancer.L3n4Addr]) error {
	// Remove orphaned backends first since [new] might again add them back.
	hadOrphan := false
	for addr := range orphans {
		be, _, ok := w.bes.Get(txn, loadbalancer.BackendByAddress(addr))
		if ok {
			if err := w.removeBackendRef(txn, serviceName, be); err != nil {
				return err
			}
		}
		hadOrphan = true
	}
	refs, err := w.updateBackends(txn, serviceName, source, LocalClusterID, new)
	if err != nil {
		return err
	}
	if hadOrphan {
		refs.Insert(serviceName)
	}

	// Refresh all frontends of services that the removed or upserted backends referenced to
	// trigger reconciliation.
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
	// Take the next revision assigned to a backend. We'll use this as a watermark to detect which backends
	// were not updated and are thus orphans that can be deleted.
	minBackendRevision := w.bes.Revision(txn) + 1

	refs, err := w.updateBackends(txn, name, source, clusterID, slices.Values(bes))
	if err != nil {
		return err
	}
	refs = refs.Insert(name) // Even for empty bes, we need to refresh this service.

	// Release orphaned backends, e.g. all backends from this source referencing this
	// service that were not updated, i.e. have old revision.
	for be, rev := range w.bes.List(txn, loadbalancer.BackendByServiceName(name)) {
		if rev >= minBackendRevision {
			continue
		}
		inst := be.GetInstanceFromSource(name, source)
		if inst == nil || inst.ClusterID != clusterID {
			continue
		}
		if err := w.removeBackendRefPerSource(txn, name, be, source, clusterID); err != nil {
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

func (w *Writer) updateBackends(txn WriteTxn, serviceName loadbalancer.ServiceName, source source.Source, clusterID uint32, bes iter.Seq[loadbalancer.BackendParams]) (sets.Set[loadbalancer.ServiceName], error) {
	// Collect all the service names linked with the updated backends in order to bump the
	// associated frontends for reconciliation.
	referencedServices := sets.New[loadbalancer.ServiceName]()

	for bep := range bes {
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
				_, _, err = w.bes.Delete(txn, be)
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
	beNew, orphan := backendRelease(be, name)
	if orphan {
		_, _, err = w.bes.Delete(txn, be)
	} else if be != beNew {
		_, _, err = w.bes.Insert(txn, beNew)
	}
	return err
}

func (w *Writer) removeBackendRefPerSource(txn WriteTxn, name loadbalancer.ServiceName, be *loadbalancer.Backend, src source.Source, clusterID uint32) (err error) {
	beNew, orphan := backendReleasePerSource(be, name, src, clusterID)
	if orphan {
		_, _, err = w.bes.Delete(txn, be)
	} else if be != beNew {
		_, _, err = w.bes.Insert(txn, beNew)
	}
	return err
}

func (w *Writer) ReleaseBackends(txn WriteTxn, name loadbalancer.ServiceName, addrs iter.Seq[loadbalancer.L3n4Addr]) error {
	changed := false
	for addr := range addrs {
		be, _, ok := w.bes.Get(txn, loadbalancer.BackendByAddress(addr))
		if !ok {
			return statedb.ErrObjectNotFound
		}

		if err := w.removeBackendRef(txn, name, be); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		return w.RefreshFrontends(txn, name)
	}
	return nil
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

func isIntLocal(fe *loadbalancer.Frontend) bool {
	switch fe.Type {
	case loadbalancer.SVCTypeClusterIP, loadbalancer.SVCTypeNodePort, loadbalancer.SVCTypeLoadBalancer, loadbalancer.SVCTypeExternalIPs:
		return fe.Service.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal
	default:
		return false
	}
}

func shouldUseLocalBackends(fe *loadbalancer.Frontend) bool {
	// When both traffic policies are Local, there is only the external scope, which
	// should contain node-local backends only. Checking isExtLocal is still enough.
	switch fe.Address.Scope() {
	case loadbalancer.ScopeExternal:
		if fe.Type == loadbalancer.SVCTypeClusterIP {
			// ClusterIP doesn't support externalTrafficPolicy and has only the
			// external scope, which contains only node-local backends when
			// internalTrafficPolicy=Local.
			return isIntLocal(fe)
		}
		return isExtLocal(fe)
	case loadbalancer.ScopeInternal:
		return isIntLocal(fe)
	default:
		return false
	}
}

func backendRelease(be *loadbalancer.Backend, name loadbalancer.ServiceName) (*loadbalancer.Backend, bool) {
	instances := be.Instances
	if be.Instances.Len() == 1 {
		// If this is the last instance avoid the allocation.
		for k := range be.Instances.All() {
			if k.ServiceName == name {
				return nil, true
			}
		}
	}
	for k := range be.GetInstancesOfService(name) {
		instances = instances.Delete(k)
	}
	beCopy := *be
	beCopy.Instances = instances
	return &beCopy, beCopy.Instances.Len() == 0
}

func backendReleasePerSource(be *loadbalancer.Backend, name loadbalancer.ServiceName, source source.Source, clusterID uint32) (*loadbalancer.Backend, bool) {
	for k, inst := range be.GetInstancesOfService(name) {
		if inst.Source == source && inst.ClusterID == clusterID {
			if be.Instances.Len() == 1 {
				// This was the last instance.
				return nil, true
			}
			beCopy := *be
			beCopy.Instances = beCopy.Instances.Delete(k)
			return &beCopy, beCopy.Instances.Len() == 0
		}
	}
	return be, false
}
