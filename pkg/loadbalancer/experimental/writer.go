// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
)

// Writer provides validated write access to the service load-balancing state.
type Writer struct {
	log       *slog.Logger
	db        *statedb.DB
	nodeAddrs statedb.Table[tables.NodeAddress]
	svcs      statedb.RWTable[*Service]
	fes       statedb.RWTable[*Frontend]
	bes       statedb.RWTable[*Backend]

	svcHooks []ServiceHook
}

type writerParams struct {
	cell.In

	Config        Config
	Log           *slog.Logger
	DB            *statedb.DB
	NodeAddresses statedb.Table[tables.NodeAddress]
	Services      statedb.RWTable[*Service]
	Frontends     statedb.RWTable[*Frontend]
	Backends      statedb.RWTable[*Backend]

	ServiceHooks []ServiceHook `group:"service-hooks"`
}

func NewWriter(p writerParams) (*Writer, error) {
	if !p.Config.EnableExperimentalLB {
		return nil, nil
	}
	w := &Writer{
		log:       p.Log,
		db:        p.DB,
		bes:       p.Backends,
		fes:       p.Frontends,
		svcs:      p.Services,
		nodeAddrs: p.NodeAddresses,
		svcHooks:  p.ServiceHooks,
	}
	return w, nil
}

func (w *Writer) IsEnabled() bool {
	return w != nil
}

type WriteTxn struct {
	statedb.WriteTxn
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
func (w *Writer) Services() statedb.Table[*Service] {
	return w.svcs
}

// Frontends returns the frontend table for reading.
// Convenience method for reducing dependencies.
func (w *Writer) Frontends() statedb.Table[*Frontend] {
	return w.fes
}

// Backends returns the backend table for reading.
// Convenience method for reducing dependencies.
func (w *Writer) Backends() statedb.Table[*Backend] {
	return w.bes
}

// ReadTxn returns a StateDB read transaction. Convenience method to
// be used with the above table getters.
func (w *Writer) ReadTxn() statedb.ReadTxn {
	return w.db.ReadTxn()
}

// WriteTxn returns a write transaction against services & backends and other additional
// tables to be used with the methods of [Writer]. The returned transaction MUST be
// Abort()'ed or Commit()'ed.
func (w *Writer) WriteTxn(extraTables ...statedb.TableMeta) WriteTxn {
	return WriteTxn{
		w.db.WriteTxn(w.svcs, append(extraTables, w.bes, w.fes)...),
	}
}

func (w *Writer) UpsertService(txn WriteTxn, svc *Service) (old *Service, err error) {
	for _, hook := range w.svcHooks {
		hook(txn, svc)
	}
	old, _, err = w.svcs.Insert(txn, svc)
	if err == nil {
		err = w.updateServiceReferences(txn, svc)
	}
	return old, err
}

func (w *Writer) UpsertFrontend(txn WriteTxn, params FrontendParams) (old *Frontend, err error) {
	// Lookup the service associated with the frontend. A frontend cannot be added
	// without the service already existing.
	svc, _, found := w.svcs.Get(txn, ServiceByName(params.ServiceName))
	if !found {
		return nil, ErrServiceNotFound
	}
	fe := w.newFrontend(txn, params, svc)
	old, _, err = w.fes.Insert(txn, fe)
	return old, err
}

// UpsertServiceAndFrontends upserts the service and updates the set of associated frontends.
// Any frontends that do not exist in the new set are deleted.
func (w *Writer) UpsertServiceAndFrontends(txn WriteTxn, svc *Service, fes ...FrontendParams) error {
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
		fe := w.newFrontend(txn, params, svc)
		if _, _, err := w.fes.Insert(txn, fe); err != nil {
			return err
		}
	}

	// Delete orphan frontends
	for fe := range w.fes.List(txn, FrontendByServiceName(svc.Name)) {
		if newAddrs.Has(fe.Address) {
			continue
		}
		if _, _, err := w.fes.Delete(txn, fe); err != nil {
			return err
		}
	}

	return nil
}

// TODO: Rework this by running a job that monitors the nodePortAddrs and updates the table when they
// change. And keep the latest copy around to fill in to avoid allocating a new slice every time.
// ... or alternatively make statedb's List() return a iter.Seq that can be iterated multiple times. Just
// need to make sure it references minimal part of the radix tree to avoid holding on to too much
// potentially stale data. Keeping [Writer] stateless would be nice.
func (w *Writer) nodePortAddrs(txn statedb.ReadTxn) []netip.Addr {
	return statedb.Collect(
		statedb.Map(
			w.nodeAddrs.List(txn, tables.NodeAddressNodePortIndex.Query(true)),
			func(addr tables.NodeAddress) netip.Addr { return addr.Addr }),
	)
}

func (w *Writer) updateServiceReferences(txn WriteTxn, svc *Service) error {
	for fe := range w.fes.List(txn, FrontendByServiceName(svc.Name)) {
		fe = fe.Clone()
		fe.service = svc
		w.refreshFrontend(txn, fe)
		if _, _, err := w.fes.Insert(txn, fe); err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) newFrontend(txn statedb.ReadTxn, params FrontendParams, svc *Service) *Frontend {
	fe := &Frontend{
		FrontendParams: params,
		service:        svc,
	}
	w.refreshFrontend(txn, fe)
	return fe
}

func (w *Writer) refreshFrontend(txn statedb.ReadTxn, fe *Frontend) {
	fe.Status = reconciler.StatusPending()
	fe.Backends = getBackendsForFrontend(txn, w.bes, fe)

	if fe.Type == loadbalancer.SVCTypeNodePort ||
		fe.Type == loadbalancer.SVCTypeHostPort {
		// Fill in the addresses for NodePort/HostPort expansion. These are expanded by the reconciler
		// into additional frontends.
		fe.nodePortAddrs = w.nodePortAddrs(txn)
	}
}

func (w *Writer) refreshFrontendsOfService(txn WriteTxn, name loadbalancer.ServiceName) error {
	for fe := range w.fes.List(txn, FrontendByServiceName(name)) {
		fe = fe.Clone()
		w.refreshFrontend(txn, fe)
		if _, _, err := w.fes.Insert(txn, fe); err != nil {
			return err
		}
	}
	return nil
}

func getBackendsForFrontend(txn statedb.ReadTxn, tbl statedb.Table[*Backend], fe *Frontend) []BackendWithRevision {
	out := []BackendWithRevision{}
	for be, rev := range tbl.List(txn, BackendByServiceName(fe.ServiceName)) {
		if be.L3n4Addr.IsIPv6() != fe.Address.IsIPv6() {
			continue
		}
		if fe.PortName != "" {
			// A backend with specific port name requested. Look up what this backend
			// is called for this service.
			instance, found := be.Instances.Get(fe.ServiceName)
			if !found {
				continue
			}
			if string(fe.PortName) != instance.PortName {
				continue
			}
		}
		out = append(out, BackendWithRevision{be, rev})
	}
	return out
}

func (w *Writer) DeleteServiceAndFrontends(txn WriteTxn, name loadbalancer.ServiceName) error {
	svc, _, found := w.svcs.Get(txn, ServiceByName(name))
	if !found {
		return statedb.ErrObjectNotFound
	}
	return w.deleteService(txn, svc)
}

func (w *Writer) deleteService(txn WriteTxn, svc *Service) error {
	// Delete the frontends
	for fe := range w.fes.List(txn, FrontendByServiceName(svc.Name)) {
		if _, _, err := w.fes.Delete(txn, fe); err != nil {
			return err
		}
	}

	// Release references to the backends
	for be := range w.bes.List(txn, BackendByServiceName(svc.Name)) {
		be, orphan := be.release(svc.Name)
		if orphan {
			if _, _, err := w.bes.Delete(txn, be); err != nil {
				return err
			}
		} else {
			if _, _, err := w.bes.Insert(txn, be); err != nil {
				return err
			}
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

// UpsertBackends adds/updates backends for the given service.
func (w *Writer) UpsertBackends(txn WriteTxn, serviceName loadbalancer.ServiceName, source source.Source, bes ...BackendParams) error {
	refs, err := w.updateBackends(txn, serviceName, source, bes)
	if err != nil {
		return err
	}

	for svc := range refs {
		if err := w.refreshFrontendsOfService(txn, svc); err != nil {
			return err
		}
	}
	return nil
}

// SetBackends sets the backends associated with a service. Existing backends from this source that
// are associated with the service but are not given are released.
func (w *Writer) SetBackends(txn WriteTxn, name loadbalancer.ServiceName, source source.Source, bes ...BackendParams) error {
	addrs := sets.New[loadbalancer.L3n4Addr]()
	for _, be := range bes {
		addrs.Insert(be.L3n4Addr)
	}
	orphans := statedb.Filter(
		w.bes.List(txn, BackendByServiceName(name)),
		func(be *Backend) bool { return !addrs.Has(be.L3n4Addr) })

	refs, err := w.updateBackends(txn, name, source, bes)
	if err != nil {
		return err
	}

	// Release orphaned backends, e.g. all backends from this source referencing this
	// service.
	for orphan := range orphans {
		for _, inst := range orphan.Instances.All() {
			if inst.Source == source {
				if err := w.removeBackendRef(txn, name, orphan); err != nil {
					return err
				}
			}
			break
		}
	}

	// Recompute the backends associated with each frontend.
	for svc := range refs {
		if err := w.refreshFrontendsOfService(txn, svc); err != nil {
			return err
		}
	}

	return nil
}

func (w *Writer) SetBackendHealth(txn WriteTxn, addr loadbalancer.L3n4Addr, healthy bool) error {
	be, _, found := w.bes.Get(txn, BackendByAddress(addr))
	if !found {
		return nil
	}

	newState := loadbalancer.BackendStateActive
	if !healthy {
		newState = loadbalancer.BackendStateQuarantined
	}

	if be.State == newState {
		return nil
	}

	switch be.State {
	case loadbalancer.BackendStateActive:
	case loadbalancer.BackendStateQuarantined:
	default:
		// Backend in maintenance mode or terminating. Ignore the health update.
		return nil
	}

	be = be.Clone()
	be.State = newState
	_, _, err := w.bes.Insert(txn, be)
	return err
}

// computeBackendState computes the new state of the backend by looking at the previous
// computed state and the state of all instances.
func computeBackendState(be *Backend) loadbalancer.BackendState {
	instanceState := loadbalancer.BackendStateActive
	for _, instance := range be.Instances.All() {
		// The only states accepted from the instances are Active, Terminating or Maintenance.
		// Quarantined can only be set via SetBackendHealth.
		switch instance.State {
		case loadbalancer.BackendStateTerminating:
			fallthrough
		case loadbalancer.BackendStateMaintenance:
			instanceState = instance.State
		}
	}

	if be.State == loadbalancer.BackendStateQuarantined &&
		instanceState == loadbalancer.BackendStateActive {
		// Quarantined backend stays quarantined.
		return loadbalancer.BackendStateQuarantined
	}
	return instanceState
}

func (w *Writer) updateBackends(txn WriteTxn, serviceName loadbalancer.ServiceName, source source.Source, bes []BackendParams) (sets.Set[loadbalancer.ServiceName], error) {
	// Collect all the service names linked with the updated backends in order to bump the
	// associated frontends for reconciliation.
	referencedServices := sets.New[loadbalancer.ServiceName]()

	for _, bep := range bes {
		var be Backend
		be.L3n4Addr = bep.L3n4Addr

		if old, _, ok := w.bes.Get(txn, BackendByAddress(bep.L3n4Addr)); ok {
			be = *old
		}

		// FIXME: How would we merge mismatching information about these?
		if bep.NodeName != "" {
			be.NodeName = bep.NodeName
		}
		if bep.ZoneID != 0 {
			be.ZoneID = bep.ZoneID
		}

		be.Instances = be.Instances.Set(
			serviceName,
			BackendInstance{
				PortName: bep.PortName,
				Weight:   bep.Weight,
				Source:   source,
				State:    bep.State,
			},
		)

		// Recompute the backend state with this new instance.
		be.State = computeBackendState(&be)

		if _, _, err := w.bes.Insert(txn, &be); err != nil {
			return nil, err
		}

		for name := range be.Instances.All() {
			referencedServices.Insert(name)
		}
	}
	return referencedServices, nil
}

func (w *Writer) DeleteBackendsBySource(txn WriteTxn, source source.Source) error {
	// Iterating over all as this is a rare operation and it would be costly
	// to always index by source.
	names := sets.New[loadbalancer.ServiceName]()
	for be := range w.bes.All(txn) {
		for name, inst := range be.Instances.All() {
			if inst.Source == source {
				names.Insert(name)
				w.removeBackendRef(txn, name, be)
			}
		}
	}

	// Mark the frontends of all referenced services as pending to reconcile the
	// deleted backends. We need to reconcile every frontend to update the references
	// to the backends in the services and maglev BPF maps.
	for name := range names {
		if err := w.refreshFrontendsOfService(txn, name); err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) removeBackendRef(txn WriteTxn, name loadbalancer.ServiceName, be *Backend) (err error) {
	be, orphan := be.release(name)
	if orphan {
		_, _, err = w.bes.Delete(txn, be)
	} else {
		_, _, err = w.bes.Insert(txn, be)
	}
	return err
}

func (w *Writer) ReleaseBackend(txn WriteTxn, name loadbalancer.ServiceName, addr loadbalancer.L3n4Addr) error {
	be, _, ok := w.bes.Get(txn, BackendByAddress(addr))
	if !ok {
		return statedb.ErrObjectNotFound
	}

	if err := w.removeBackendRef(txn, name, be); err != nil {
		return err
	}
	return w.refreshFrontendsOfService(txn, name)
}

func (w *Writer) ReleaseBackendsFromSource(txn WriteTxn, name loadbalancer.ServiceName, source source.Source) error {
	for be := range w.bes.List(txn, BackendByServiceName(name)) {
		for instName, inst := range be.Instances.All() {
			if inst.Source != source || instName != name {
				continue
			}
			if err := w.removeBackendRef(txn, name, be); err != nil {
				return err
			}
			break
		}
	}
	return w.refreshFrontendsOfService(txn, name)
}

func (w *Writer) DebugDump(txn statedb.ReadTxn, to io.Writer) {
	tw := tabwriter.NewWriter(to, 5, 0, 3, ' ', 0)

	fmt.Fprintln(tw, "--- Services ---")
	fmt.Fprintln(tw, strings.Join((*Service)(nil).TableHeader(), "\t"))
	for svc := range w.svcs.All(txn) {
		fmt.Fprintln(tw, strings.Join(svc.TableRow(), "\t"))
	}

	fmt.Fprintln(tw, "\n--- Frontends ---")
	fmt.Fprintln(tw, strings.Join((*Frontend)(nil).TableHeader(), "\t"))
	for fe := range w.fes.All(txn) {
		fmt.Fprintln(tw, strings.Join(fe.TableRow(), "\t"))
	}

	fmt.Fprintln(tw, "\n--- Backends ---")
	fmt.Fprintln(tw, strings.Join((*Backend)(nil).TableHeader(), "\t"))
	for be := range w.bes.All(txn) {
		fmt.Fprintln(tw, strings.Join(be.TableRow(), "\t"))
	}

	tw.Flush()
}
