package tables

import (
	"errors"
	"time"

	iradix "github.com/hashicorp/go-immutable-radix/v2"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

type ServiceProperty = any

type ServiceParams struct {
	loadbalancer.L3n4Addr

	Labels labels.Labels
	Source source.Source

	Type loadbalancer.SVCType

	NatPolicy                loadbalancer.SVCNatPolicy
	ExtPolicy, IntPolicy     loadbalancer.SVCTrafficPolicy
	LoadBalancerSourceRanges []*cidr.CIDR
	LoopbackHostPort         bool

	SessionAffinity *ServiceSessionAffinity
	HealthCheck     *ServiceHealthCheck

	Properties *iradix.Tree[ServiceProperty]
}

func (sp *ServiceParams) SetProperty(name string, value any) *ServiceParams {
	sp2 := *sp
	sp2.Properties, _, _ = sp2.Properties.Insert([]byte(name), value)
	return &sp2
}

func (sp *ServiceParams) UnsetProperty(name string) *ServiceParams {
	sp2 := *sp
	sp2.Properties, _, _ = sp2.Properties.Delete([]byte(name))
	return &sp2
}

func (sp *ServiceParams) GetProperty(name string) (ServiceProperty, bool) {
	return sp.Properties.Get([]byte(name))
}

type Service struct {
	ID   loadbalancer.ID
	Name loadbalancer.ServiceName

	// Params contains the service details. This can be nil if the service is partial
	// (e.g. backends or redirects have been set before service details).
	Params *ServiceParams

	// BackendRevision is the backends table revision of the latest updated backend
	// that references this service. In other words, this field is updated every time
	// a backend that refers to this service updates. This allows watching the changes
	// to the service and its referenced backends by only watching the service table.
	// The reconciler for the BPF maps only watches the service and queries for the
	// backends during the reconciliation operation.
	//
	// TODO: Potentially come up with a better way that is still conceptually simple
	// and allows efficient query for the backends?
	BackendRevision statedb.Revision

	L7Redirect    *ServiceL7Redirect
	LocalRedirect *ServiceLocalRedirect

	// BPFStatus is the reconciliation status of the BPF maps for this service.
	BPFStatus reconciler.Status
}

// Clone returns a shallow copy of the service.
func (s *Service) Clone() *Service {
	s2 := *s
	return &s2
}

func (s *Service) WithBPFStatus(status reconciler.Status) *Service {
	s = s.Clone()
	s.BPFStatus = status
	return s
}

func (s *Service) GetBPFStatus() reconciler.Status {
	return s.BPFStatus
}

type ServiceL7Redirect struct {
	OwnerName, OwnerNamespace string
	ProxyPort                 uint16
}

type ServiceLocalRedirect struct {
}

type ServiceSessionAffinity struct {
	Timeout time.Duration
}

type ServiceHealthCheck struct {
	NodePort uint16
}

var (
	ServiceNameIndex = statedb.Index[*Service, loadbalancer.ServiceName]{
		Name: "name",
		FromObject: func(obj *Service) index.KeySet {
			return index.NewKeySet(index.Stringer(obj.Name))
		},
		FromKey: index.Stringer[loadbalancer.ServiceName],
		Unique:  true,
	}

	ServiceSourceIndex = statedb.Index[*Service, source.Source]{
		Name: "source",
		FromObject: func(obj *Service) index.KeySet {
			if obj.Params == nil {
				return index.NewKeySet()
			}
			return index.NewKeySet(index.Stringer(obj.Params.Source))
		},
		FromKey: index.Stringer[source.Source],
		Unique:  false,
	}

	ServiceAddrIndex = statedb.Index[*Service, loadbalancer.L3n4Addr]{
		Name: "source",
		FromObject: func(obj *Service) index.KeySet {
			if obj.Params == nil {
				// Don't index partial services that may not yet have an address.
				return index.NewKeySet()
			}
			return index.NewKeySet(l3n4AddrKey(obj.Params.L3n4Addr))
		},
		FromKey: l3n4AddrKey,
		Unique:  false, // TODO should be unique?
	}
)

const (
	ServicesTableName = "services"
)

func NewServicesTable(db *statedb.DB) (statedb.RWTable[*Service], error) {
	tbl, err := statedb.NewTable(
		ServicesTableName,
		ServiceNameIndex,
		ServiceSourceIndex,
		ServiceAddrIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

// TODOs:
// - Should we segregate backends by state at this level or when reconciling the service?
// - Where should the Service's BPF ID be assigned? Seems very much like a low-level concern.
//   Though for debugging it would be great to be part of the struct. The ID can only be
//   released when it's deleted from BPF side, so it might be that this should be managed by
//   the reconciler. Do we need write access to the object in the reconciler operation to be
//   able to fill this in? E.g. Update() would allocate the ID and fill it in. Delete would
//   release it. Benefit of this would be that we can "overflow" the table and on deletion
//   IDs would become available and Update of a "overflowed" object would be able to acquire
//   the ID.
//

// Services provides safe access to manipulating the services table in a semantics-preserving
// way.
type Services struct {
	db   *statedb.DB
	svcs statedb.RWTable[*Service]
	bes  statedb.RWTable[*Backend]

	idAlloc        *service.IDAllocator
	backendIDAlloc *service.IDAllocator
}

type ServiceWriteTxn struct {
	statedb.WriteTxn
}

var (
	ErrServiceSourceMismatch = errors.New("Service exists from different source")
)

// WriteTxn returns a write transaction against services & backends and other additional
// tables to be used with the methods of [Services]. The returned transaction MUST be
// Abort()'ed or Commit()'ed.
func (s *Services) WriteTxn(extraTables ...statedb.TableMeta) ServiceWriteTxn {
	return ServiceWriteTxn{
		s.db.WriteTxn(s.svcs, append(extraTables, s.bes)...),
	}
}

func (s *Services) UpsertService(txn ServiceWriteTxn, name loadbalancer.ServiceName, params ServiceParams) error {
	var svc Service

	old, _, found := s.svcs.First(txn, ServiceNameIndex.Query(name))
	if found {
		// Do not allow overriding a service that has been created from
		// another source. If the service is 'Unspec'
		if old.Params != nil && old.Params.Source != params.Source {
			return ErrServiceSourceMismatch
		}
		svc = *old
	}
	if svc.ID == 0 {
		id, err := s.idAlloc.AcquireID(params.L3n4Addr)
		if err != nil {
			return err
		}
		svc.ID = id.ID

	}
	svc.Params = &params
	svc.BPFStatus = reconciler.StatusPending()
	_, _, err := s.svcs.Insert(txn, &svc)
	return err
}

// ModifyService modifies an existing service with a modify function. The service struct passed to the function
// can be modified, but any fields that are by pointer must be cloned before modification!
// TODO: Is this method useful?
func (s *Services) ModifyService(txn ServiceWriteTxn, name loadbalancer.ServiceName, modify func(*ServiceParams) error) error {
	svc, _, found := s.svcs.First(txn, ServiceNameIndex.Query(name))
	if !found {
		return statedb.ErrObjectNotFound
	}
	var params ServiceParams
	if svc.Params != nil {
		params = *svc.Params
	}
	if err := modify(&params); err != nil {
		return err
	}
	svc = svc.Clone()
	svc.Params = &params
	svc.BPFStatus = reconciler.StatusPending()
	_, _, err := s.svcs.Insert(txn, svc)
	return err
}

func (s *Services) DeleteService(txn ServiceWriteTxn, name loadbalancer.ServiceName, source source.Source) error {
	svc, _, found := s.svcs.First(txn, ServiceNameIndex.Query(name))
	if !found {
		return statedb.ErrObjectNotFound
	}
	return s.deleteService(txn, svc)
}

func (s *Services) deleteService(txn ServiceWriteTxn, svc *Service) error {
	// Release references to the backends
	// TODO: Who reconciles the deletion of the backends? If a service is being
	// deleted, do we care if the backends are deleted before the service from the BPF map?
	// This way we could have both a service reconciler and a backend reconciler and we can
	// have the service reconciler also do backend updates to make sure they're done before
	// the service. The reconcilers would co-operate to avoid unnecessary backend updates
	// (compare-and-swap of backend revision).
	iter, _ := s.bes.Get(txn, BackendServiceIndex.Query(svc.Name))
	for be, _, ok := iter.Next(); ok; be, _, ok = iter.Next() {
		be = be.removeRef(svc.Name)
		if _, _, err := s.bes.Insert(txn, be); err != nil {
			return err
		}
	}

	svc = svc.Clone()
	if svc.ID != 0 {
		s.idAlloc.ReleaseID(svc.ID)
		svc.ID = 0
	}

	svc.BPFStatus = reconciler.StatusPendingDelete()
	_, _, err := s.svcs.Insert(txn, svc)
	return err
}

func (s *Services) DeleteServices(txn ServiceWriteTxn, source source.Source) error {
	iter, _ := s.svcs.Get(txn, ServiceSourceIndex.Query(source))
	for svc, _, ok := iter.Next(); ok; svc, _, ok = iter.Next() {
		if err := s.deleteService(txn, svc); err != nil {
			return err
		}
	}
	return nil
}

func (s *Services) UpsertBackends(txn ServiceWriteTxn, name loadbalancer.ServiceName, bes ...BackendParams) error {
	var svc Service

	old, _, found := s.svcs.First(txn, ServiceNameIndex.Query(name))
	if found {
		svc = *old
	} else {
		svc.Name = name
	}
	if err := s.updateBackends(txn, &svc, bes); err != nil {
		return err
	}
	_, _, err := s.svcs.Insert(txn, &svc)
	return err
}

func (s *Services) updateBackends(txn ServiceWriteTxn, svc *Service, bes []BackendParams) error {
	existing := make(map[loadbalancer.L3n4Addr]*Backend)
	iter, _ := s.bes.Get(txn, BackendServiceIndex.Query(svc.Name))
	for be, _, ok := iter.Next(); ok; be, _, ok = iter.Next() {
		existing[be.L3n4Addr] = be
	}

	for _, bep := range bes {
		var be Backend

		if old, ok := existing[bep.L3n4Addr]; ok {
			if old.Source != be.Source {
				// FIXME likely want to be able to have many sources for
				// a backend.
				return ErrServiceSourceMismatch
			}
			be = *old
			// FIXME how to merge the other fields?
		} else {
			id, err := s.backendIDAlloc.AcquireID(be.L3n4Addr)
			if err != nil {
				return err
			}
			be.ID = loadbalancer.BackendID(id.ID)
		}
		be.BackendParams = bep
		be.ReferencedBy = be.ReferencedBy.Insert(svc.Name)

		if _, _, err := s.bes.Insert(txn, &be); err != nil {
			return err
		}
	}

	svc.BPFStatus = reconciler.StatusPending()
	svc.BackendRevision = s.bes.Revision(txn)
	return nil
}

func (s *Services) DeleteBackend(txn ServiceWriteTxn, name loadbalancer.ServiceName, addr loadbalancer.L3n4Addr) error {
	svc, _, ok := s.svcs.First(txn, ServiceNameIndex.Query(name))
	if !ok {
		return statedb.ErrObjectNotFound
	}

	be, _, ok := s.bes.First(txn, BackendAddrIndex.Query(addr))
	if !ok {
		return statedb.ErrObjectNotFound
	}
	_, _, err := s.bes.Insert(txn, be.removeRef(name))
	if err != nil {
		return statedb.ErrObjectNotFound
	}

	svc = svc.Clone()
	svc.BackendRevision = s.bes.Revision(txn)
	svc.BPFStatus = reconciler.StatusPending()
	_, _, err = s.svcs.Insert(txn, svc)
	return err
}

func (s *Services) DeleteBackends(txn ServiceWriteTxn, name loadbalancer.ServiceName, source source.Source) error {
	panic("TBD")
}

func (s *Services) UpsertL7Redirect(txn ServiceWriteTxn, name loadbalancer.ServiceName, l7 ServiceL7Redirect) error {
	var svc Service

	if old, _, ok := s.svcs.First(txn, ServiceNameIndex.Query(name)); ok {
		svc = *old
	} else {
		svc.Name = name
	}
	svc.L7Redirect = &l7
	svc.BPFStatus = reconciler.StatusPending()

	_, _, err := s.svcs.Insert(txn, &svc)
	return err
}

func (s *Services) DeleteL7Redirect(txn ServiceWriteTxn, name loadbalancer.ServiceName) error {
	var svc Service

	if old, _, ok := s.svcs.First(txn, ServiceNameIndex.Query(name)); ok {
		svc = *old
	} else {
		svc.Name = name
	}
	svc.L7Redirect = nil
	svc.BPFStatus = reconciler.StatusPending()
	_, _, err := s.svcs.Insert(txn, &svc)
	return err
}
