package tables

import (
	"errors"
	"time"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

type ServiceParams struct {
	L3n4Addr loadbalancer.L3n4Addr
	Type     loadbalancer.SVCType
	Labels   labels.Labels
	Source   source.Source

	NatPolicy                loadbalancer.SVCNatPolicy
	ExtPolicy, IntPolicy     loadbalancer.SVCTrafficPolicy
	LoadBalancerSourceRanges container.ImmSet[*cidr.CIDR]
	LoopbackHostPort         bool

	SessionAffinity *ServiceSessionAffinity
	HealthCheck     *ServiceHealthCheck
}

type Service struct {
	Name loadbalancer.ServiceName

	ServiceParams

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

	L7Redirect *ServiceL7Redirect

	// LocalRedirect when not nil will force use of local pod backends.
	// When the LocalRedirect is removed the original service is restored.
	// TODO: The controller that manages these will need to constantly watch services
	// in order to set this when a service is added or removed. Same for L7. Is there
	// any downside to these being updated asynchronously/with a delay?
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
	// TODO how to avoid the direct references to the backends here?
	Backends []loadbalancer.L3n4Addr
}

type ServiceSessionAffinity struct {
	Timeout time.Duration
}

type ServiceHealthCheck struct {
	NodePort uint16
}

var (
	ServiceL3n4AddrIndex = statedb.Index[*Service, loadbalancer.L3n4Addr]{
		Name: "addr",
		FromObject: func(obj *Service) index.KeySet {
			return index.NewKeySet(l3n4AddrKey(obj.L3n4Addr))
		},
		FromKey: l3n4AddrKey,
		Unique:  true,
	}

	ServiceNameIndex = statedb.Index[*Service, loadbalancer.ServiceName]{
		Name: "name",
		FromObject: func(obj *Service) index.KeySet {
			return index.NewKeySet(index.Stringer(obj.Name))
		},
		FromKey: index.Stringer[loadbalancer.ServiceName],
		Unique:  false,
	}

	ServiceStatusIndex = reconciler.NewStatusIndex[*Service]((*Service).GetBPFStatus)
)

const (
	ServicesTableName = "services"
)

func NewServicesTable(db *statedb.DB) (statedb.RWTable[*Service], error) {
	tbl, err := statedb.NewTable(
		ServicesTableName,
		ServiceL3n4AddrIndex,
		ServiceNameIndex,
		ServiceStatusIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

var ServicesCell = cell.Module(
	"services",
	"Services",

	cell.ProvidePrivate(
		NewServicesTable,
		NewBackendsTable,

		serviceReconcilerConfig,
	),
	cell.Provide(
		NewServices,
		statedb.RWTable[*Service].ToTable,
		statedb.RWTable[*Backend].ToTable,
	),
	cell.Invoke(reconciler.Register[*Service]),
)

func NewServices(db *statedb.DB, svcs statedb.RWTable[*Service], bes statedb.RWTable[*Backend]) (*Services, error) {
	return &Services{db, svcs, bes}, nil
}

// Services provides safe access to manipulating the services table in a semantics-preserving
// way.
type Services struct {
	db   *statedb.DB
	svcs statedb.RWTable[*Service]
	bes  statedb.RWTable[*Backend]
}

type ServiceWriteTxn struct {
	statedb.WriteTxn
}

var (
	ErrServiceSourceMismatch = errors.New("service exists from different source")
	ErrServiceConflict       = errors.New("conflict with a service with same address, but different name")
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

	existing, _, found := s.svcs.First(txn, ServiceL3n4AddrIndex.Query(params.L3n4Addr))
	if found {
		// Do not allow services with same address but different names to override each other.
		if !existing.Name.Equal(name) {
			return ErrServiceConflict
		}

		// Do not allow overriding a service that has been created from
		// another source. If the service is 'Unspec'
		if existing.Source != params.Source {
			return ErrServiceSourceMismatch
		}

		// Merge the existing fields.
		svc = *existing
	}
	svc.Name = name
	svc.ServiceParams = params
	svc.BPFStatus = reconciler.StatusPending()
	_, _, err := s.svcs.Insert(txn, &svc)
	return err
}

func (s *Services) DeleteServicesByName(txn ServiceWriteTxn, name loadbalancer.ServiceName, source source.Source) error {
	svc, _, found := s.svcs.First(txn, ServiceNameIndex.Query(name))
	if !found {
		return statedb.ErrObjectNotFound
	}
	if svc.Source != source {
		return ErrServiceSourceMismatch
	}

	return s.deleteService(txn, svc)
}

func (s *Services) deleteService(txn ServiceWriteTxn, svc *Service) error {
	// Release references to the backends
	iter, _ := s.bes.Get(txn, BackendServiceIndex.Query(svc.Name))
	for be, _, ok := iter.Next(); ok; be, _, ok = iter.Next() {
		be, orphan := be.removeRef(svc.Name)
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

	svc.BPFStatus = reconciler.StatusPendingDelete()
	_, _, err := s.svcs.Insert(txn, svc)
	return err
}

func (s *Services) DeleteServicesBySource(txn ServiceWriteTxn, source source.Source) error {
	/*iter, _ := s.svcs.Get(txn, ServiceSourceIndex.Query(source))
	for svc, _, ok := iter.Next(); ok; svc, _, ok = iter.Next() {
		if err := s.deleteService(txn, svc); err != nil {
			return err
		}
	}*/
	return nil
}

func (s *Services) UpsertBackends(txn ServiceWriteTxn, name loadbalancer.ServiceName, bes ...BackendParams) error {
	// TODO: Do we want the ability to do a "sub-transaction" that can be aborted? Here we may do partial
	// updates and return an error and are assuming the caller will abort the transaction, but not sure if
	// that's a safe design.

	if err := s.updateBackends(txn, name, bes); err != nil {
		return err
	}

	iter, _ := s.svcs.Get(txn, ServiceNameIndex.Query(name))
	for svc, _, ok := iter.Next(); ok; svc, _, ok = iter.Next() {
		svc = svc.Clone()
		svc.BPFStatus = reconciler.StatusPending()
		svc.BackendRevision = s.bes.Revision(txn)
		if _, _, err := s.svcs.Insert(txn, svc); err != nil {
			return err
		}
	}
	return nil
}

type serviceNameSet = container.ImmSet[loadbalancer.ServiceName]

func newServiceNameSet(names ...loadbalancer.ServiceName) container.ImmSet[loadbalancer.ServiceName] {
	return container.NewImmSetFunc(
		loadbalancer.ServiceName.Compare,
		names...,
	)
}

func (s *Services) updateBackends(txn ServiceWriteTxn, name loadbalancer.ServiceName, bes []BackendParams) error {
	for _, bep := range bes {
		var be Backend

		if old, _, ok := s.bes.First(txn, BackendAddrIndex.Query(bep.L3n4Addr)); ok {
			if old.Source != be.Source {
				// FIXME likely want to be able to have many sources for
				// a backend?
				return ErrServiceSourceMismatch
			}
			be = *old
			// FIXME how to merge the other fields?
			be.ReferencedBy = be.ReferencedBy.Insert(name)
		} else {
			be.ReferencedBy = newServiceNameSet(name)
		}
		be.BackendParams = bep

		if _, _, err := s.bes.Insert(txn, &be); err != nil {
			return err
		}
	}
	return nil
}

func (s *Services) DeleteBackendsBySource(txn ServiceWriteTxn, source source.Source) error {
	log.Errorf("TODO implement DeleteBackendsBySource")
	return nil
}

func (s *Services) DeleteBackend(txn ServiceWriteTxn, name loadbalancer.ServiceName, addr loadbalancer.L3n4Addr) error {
	be, _, ok := s.bes.First(txn, BackendAddrIndex.Query(addr))
	if !ok {
		return statedb.ErrObjectNotFound
	}
	be, orphan := be.removeRef(name)
	if orphan {
		if _, _, err := s.bes.Delete(txn, be); err != nil {
			return err
		}
	} else {
		if _, _, err := s.bes.Insert(txn, be); err != nil {
			return err
		}
	}

	// Bump the backend revision for each of the referenced services to force
	// reconciliation.
	revision := s.bes.Revision(txn)
	iter, _ := s.svcs.Get(txn, ServiceNameIndex.Query(name))
	for svc, _, ok := iter.Next(); ok; svc, _, ok = iter.Next() {
		svc = svc.Clone()
		svc.BackendRevision = revision
		svc.BPFStatus = reconciler.StatusPending()
		if _, _, err := s.svcs.Insert(txn, svc); err != nil {
			return err
		}
	}
	return nil
}

// TODO: This is not a great API as now the one managing the L7 redirects will need to observe services and call
// this as needed. Another alternative is to have a bit more state here to allow setting the L7 redirect on
// service insert. On the other hand making *Services stateful complicates things. This design also allows for
// greater flexibility in selecting to which services the redirect applies to (LocalRedirect needs this).
func (s *Services) SetL7Redirect(txn ServiceWriteTxn, name loadbalancer.ServiceName, addr loadbalancer.L3n4Addr, l7 *ServiceL7Redirect) error {
	svc, _, ok := s.svcs.First(txn, ServiceL3n4AddrIndex.Query(addr))
	if !ok {
		return statedb.ErrObjectNotFound
	}
	if !svc.Name.Equal(name) {
		return ErrServiceConflict
	}

	svc = svc.Clone()
	svc.BPFStatus = reconciler.StatusPending()
	svc.L7Redirect = l7
	_, _, err := s.svcs.Insert(txn, svc)
	return err
}

func (s *Services) SetLocalRedirect(txn ServiceWriteTxn, name loadbalancer.ServiceName, addr loadbalancer.L3n4Addr, lr *ServiceLocalRedirect) error {
	svc, _, ok := s.svcs.First(txn, ServiceL3n4AddrIndex.Query(addr))
	if !ok {
		return statedb.ErrObjectNotFound
	}
	if !svc.Name.Equal(name) {
		return ErrServiceConflict
	}

	svc = svc.Clone()
	svc.BPFStatus = reconciler.StatusPending()
	svc.LocalRedirect = lr
	_, _, err := s.svcs.Insert(txn, svc)
	return err
}
