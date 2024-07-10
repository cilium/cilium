// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
)

// Writer provides validated write access to the service load-balancing state.
type Writer struct {
	log  *slog.Logger
	db   *statedb.DB
	svcs statedb.RWTable[*Service]
	fes  statedb.RWTable[*Frontend]
	bes  statedb.RWTable[*Backend]
}

type lbWriterParams struct {
	cell.In

	Config    Config
	Log       *slog.Logger
	DB        *statedb.DB
	Services  statedb.RWTable[*Service]
	Frontends statedb.RWTable[*Frontend]
	Backends  statedb.RWTable[*Backend]
}

func NewWriter(p lbWriterParams) (*Writer, error) {
	if !p.Config.EnableExperimentalLB {
		return nil, nil
	}
	return &Writer{
		log:  p.Log,
		db:   p.DB,
		bes:  p.Backends,
		fes:  p.Frontends,
		svcs: p.Services,
	}, nil
}

func (s *Writer) IsEnabled() bool {
	return s != nil
}

type WriteTxn struct {
	statedb.WriteTxn
}

// Services returns the service table for reading.
// Convenience method for reducing dependencies.
func (s *Writer) Services() statedb.Table[*Service] {
	return s.svcs
}

// Frontends returns the frontend table for reading.
// Convenience method for reducing dependencies.
func (s *Writer) Frontends() statedb.Table[*Frontend] {
	return s.fes
}

// Backends returns the backend table for reading.
// Convenience method for reducing dependencies.
func (s *Writer) Backends() statedb.Table[*Backend] {
	return s.bes
}

// ReadTxn returns a StateDB read transaction. Convenience method to
// be used with the above table getters.
func (s *Writer) ReadTxn() statedb.ReadTxn {
	return s.db.ReadTxn()
}

// WriteTxn returns a write transaction against services & backends and other additional
// tables to be used with the methods of [Writer]. The returned transaction MUST be
// Abort()'ed or Commit()'ed.
func (s *Writer) WriteTxn(extraTables ...statedb.TableMeta) WriteTxn {
	return WriteTxn{
		s.db.WriteTxn(s.svcs, append(extraTables, s.bes, s.fes)...),
	}
}

func (s *Writer) UpsertService(txn WriteTxn, svc *Service) (old *Service, err error) {
	old, _, err = s.svcs.Insert(txn, svc)
	if err == nil {
		err = s.updateServiceReferences(txn, svc)
	}
	return old, err
}

func (s *Writer) UpsertFrontend(txn WriteTxn, fe *Frontend) (old *Frontend, err error) {
	fe.Status = reconciler.StatusPending()

	// Lookup the service associated with the frontend. A frontend cannot be added
	// without the service already existing.
	svc, _, found := s.svcs.Get(txn, ServiceNameIndex.Query(fe.ServiceName))
	if !found {
		return nil, ErrServiceNotFound
	}
	fe.service = svc

	old, _, err = s.fes.Insert(txn, fe)
	return old, err
}

// UpsertServiceAndFrontends upserts the service and updates the set of associated frontends.
// Any frontends that do not exist in the new set are deleted.
func (s *Writer) UpsertServiceAndFrontends(txn WriteTxn, svc *Service, fes ...*Frontend) error {
	_, _, err := s.svcs.Insert(txn, svc)
	if err != nil {
		return err
	}

	// Upsert the new frontends
	newAddrs := sets.New[loadbalancer.L3n4Addr]()
	for _, fe := range fes {
		newAddrs.Insert(fe.Address)

		fe.Status = reconciler.StatusPending()
		fe.ServiceName = svc.Name
		fe.service = svc
		if _, _, err := s.fes.Insert(txn, fe); err != nil {
			return err
		}
	}

	// Delete orphan frontends
	iter := s.fes.List(txn, FrontendServiceIndex.Query(svc.Name))
	for fe, _, ok := iter.Next(); ok; fe, _, ok = iter.Next() {
		if newAddrs.Has(fe.Address) {
			continue
		}
		if _, _, err := s.fes.Delete(txn, fe); err != nil {
			return err
		}
	}

	return nil
}

func (s *Writer) updateServiceReferences(txn WriteTxn, svc *Service) error {
	iter := s.fes.List(txn, FrontendServiceIndex.Query(svc.Name))
	for fe, _, ok := iter.Next(); ok; fe, _, ok = iter.Next() {
		fe = fe.Clone()
		fe.Status = reconciler.StatusPending()
		fe.service = svc
		if _, _, err := s.fes.Insert(txn, fe); err != nil {
			return err
		}
	}
	return nil
}

func (s *Writer) markFrontendsPending(txn WriteTxn, name loadbalancer.ServiceName) error {
	iter := s.fes.List(txn, FrontendServiceIndex.Query(name))
	for fe, _, ok := iter.Next(); ok; fe, _, ok = iter.Next() {
		fe = fe.Clone()
		fe.Status = reconciler.StatusPending()
		if _, _, err := s.fes.Insert(txn, fe); err != nil {
			return err
		}
	}
	return nil
}

func (s *Writer) DeleteServiceAndFrontends(txn WriteTxn, name loadbalancer.ServiceName) error {
	svc, _, found := s.svcs.Get(txn, ServiceNameIndex.Query(name))
	if !found {
		return statedb.ErrObjectNotFound
	}
	return s.deleteService(txn, svc)
}

func (s *Writer) deleteService(txn WriteTxn, svc *Service) error {
	// Delete the frontends
	{
		iter := s.fes.List(txn, FrontendServiceIndex.Query(svc.Name))
		for fe, _, ok := iter.Next(); ok; fe, _, ok = iter.Next() {
			if _, _, err := s.fes.Delete(txn, fe); err != nil {
				return err
			}
		}
	}

	// Release references to the backends
	{
		iter := s.bes.List(txn, BackendServiceIndex.Query(svc.Name))
		for be, _, ok := iter.Next(); ok; be, _, ok = iter.Next() {
			be, orphan := be.release(svc.Name)
			if orphan {
				if _, _, err := s.bes.Delete(txn, be); err != nil {
					return err
				}
			} else {
				if _, _, err := s.bes.Insert(txn, be); err != nil {
					return err
				}
			}
		}
	}

	// And finally delete the service itself.
	_, _, err := s.svcs.Delete(txn, svc)
	return err
}

// DeleteServicesBySource deletes all services from the specific source. This is used to
// implement "resynchronization", for example with K8s when the Watch() call fails and we need
// to start over with a List().
func (s *Writer) DeleteServicesBySource(txn WriteTxn, source source.Source) error {
	// Iterating over all as this is a rare operation and it would be costly
	// to always index by source.
	iter := s.svcs.All(txn)
	for svc, _, ok := iter.Next(); ok; svc, _, ok = iter.Next() {
		if svc.Source == source {
			if err := s.deleteService(txn, svc); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Writer) UpsertBackends(txn WriteTxn, serviceName loadbalancer.ServiceName, source source.Source, bes ...*loadbalancer.Backend) error {
	if err := s.updateBackends(txn, serviceName, source, bes); err != nil {
		return err
	}
	return s.markFrontendsPending(txn, serviceName)
}

func NewServiceNameSet(names ...loadbalancer.ServiceName) container.ImmSet[loadbalancer.ServiceName] {
	return container.NewImmSetFunc(
		loadbalancer.ServiceName.Compare,
		names...,
	)
}

func (s *Writer) updateBackends(txn WriteTxn, serviceName loadbalancer.ServiceName, source source.Source, bes []*loadbalancer.Backend) error {
	for _, bep := range bes {
		var be Backend
		if old, _, ok := s.bes.Get(txn, BackendAddrIndex.Query(bep.L3n4Addr)); ok {
			be = *old
		} else {
			be.ReferencedBy = NewServiceNameSet()
		}
		be.Backend = *bep
		be.Source = source
		be.ReferencedBy = be.ReferencedBy.Insert(serviceName)

		if _, _, err := s.bes.Insert(txn, &be); err != nil {
			return err
		}
	}
	return nil
}

func (s *Writer) DeleteBackendsBySource(txn WriteTxn, source source.Source) error {
	// Iterating over all as this is a rare operation and it would be costly
	// to always index by source.
	names := sets.New[loadbalancer.ServiceName]()
	iter := s.bes.All(txn)
	for be, _, ok := iter.Next(); ok; be, _, ok = iter.Next() {
		if be.Source == source {
			names.Insert(be.ReferencedBy.AsSlice()...)
			if _, _, err := s.bes.Delete(txn, be); err != nil {
				return err
			}
		}
	}

	// Mark the frontends of all referenced services as pending to reconcile the
	// deleted backends. We need to reconcile every frontend to update the references
	// to the backends in the services and maglev BPF maps.
	for name := range names {
		if err := s.markFrontendsPending(txn, name); err != nil {
			return err
		}
	}
	return nil
}

func (s *Writer) removeBackendRef(txn WriteTxn, name loadbalancer.ServiceName, be *Backend) (err error) {
	be, orphan := be.release(name)
	if orphan {
		_, _, err = s.bes.Delete(txn, be)
	} else {
		_, _, err = s.bes.Insert(txn, be)
	}
	return err
}

func (s *Writer) ReleaseBackend(txn WriteTxn, name loadbalancer.ServiceName, addr loadbalancer.L3n4Addr) error {
	be, _, ok := s.bes.Get(txn, BackendAddrIndex.Query(addr))
	if !ok {
		return statedb.ErrObjectNotFound
	}

	if err := s.removeBackendRef(txn, name, be); err != nil {
		return err
	}
	return s.markFrontendsPending(txn, name)
}

func (s *Writer) DebugDump(txn statedb.ReadTxn, to io.Writer) {
	w := tabwriter.NewWriter(to, 5, 0, 3, ' ', 0)

	fmt.Fprintln(w, "--- Services ---")
	fmt.Fprintln(w, strings.Join((*Service)(nil).TableHeader(), "\t"))
	iter := s.svcs.All(txn)
	for svc, _, ok := iter.Next(); ok; svc, _, ok = iter.Next() {
		fmt.Fprintln(w, strings.Join(svc.TableRow(), "\t"))
	}

	fmt.Fprintln(w, "--- Frontends ---")
	fmt.Fprintln(w, strings.Join((*Frontend)(nil).TableHeader(), "\t"))
	iterFe := s.fes.All(txn)
	for be, _, ok := iterFe.Next(); ok; be, _, ok = iterFe.Next() {
		fmt.Fprintln(w, strings.Join(be.TableRow(), "\t"))
	}

	fmt.Fprintln(w, "--- Backends ---")
	fmt.Fprintln(w, strings.Join((*Backend)(nil).TableHeader(), "\t"))
	iterBe := s.bes.All(txn)
	for be, _, ok := iterBe.Next(); ok; be, _, ok = iterBe.Next() {
		fmt.Fprintln(w, strings.Join(be.TableRow(), "\t"))
	}

	w.Flush()
}
