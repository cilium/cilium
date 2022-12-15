package servicemanager

import (
	"fmt"

	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/container"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

type frontendList []Frontend

func (l frontendList) lookup(typ lb.SVCType) *Frontend {
	for _, fe := range l {
		if fe.Type == typ {
			return &fe
		}
	}
	return nil
}

func (l frontendList) upsert(fe *Frontend) (frontendList, bool) {
	for i, other := range l {
		// TODO: reject upsert if frontend owned by another handle?
		if fe.Type == other.Type {
			l[i] = *fe
		}
	}
	l = append(l, *fe)

	// Sort the frontends by their priority based on the type.
	slices.SortFunc(l, func(a, b Frontend) bool {
		return lb.SVCPriority[a.Type] < lb.SVCPriority[b.Type]
	})

	// Return true if this newly inserted frontend is now the
	// primary.
	return l, l[0].Type == fe.Type
}

func (l frontendList) delete(typ lb.SVCType) (result frontendList, wasPrimary bool) {
	for i, info := range l {
		if info.Type == typ {
			l = slices.Delete(l, i, i+1)
			return l, i == 0
		}
	}
	return l, false
}

func (l frontendList) empty() bool {
	return len(l) == 0
}

func (l frontendList) primary() *Frontend {
	if len(l) == 0 {
		return nil
	}
	return &l[0]
}

// FIXME catch overlapping frontends across different serviceIDs!

type serviceStore map[ServiceName]*serviceEntry

// upsertFrontend creates or updates the frontend.
// Returns true if this frontend is the new primary frontend.
func (store serviceStore) upsertFrontend(name ServiceName, fe *Frontend) (bool, []*Backend) {
	entry := store[name]
	if entry == nil {
		entry = newServiceEntry(name)
		store[name] = entry
	}
	return entry.upsertFrontend(fe)
}

// deleteFrontend removes the frontend with the given address and type (if it exists). Returns the new primary
// frontend if the deletion changed it.
func (store serviceStore) deleteFrontend(
	name ServiceName,
	addr lb.L3n4Addr,
	svcType lb.SVCType,
) (primary *Frontend, backends []*Backend) {
	entry := store[name]
	if entry != nil {
		return entry.deleteFrontend(addr, svcType)
	}
	return nil, nil
}

func (store serviceStore) upsertBackends(name ServiceName, backends []*Backend) {
	entry := store[name]
	if entry == nil {
		entry = newServiceEntry(name)
		store[name] = entry
	}
	entry.upsertBackends(backends)
}

func (store serviceStore) forEachActiveFrontend(name ServiceName, fn func(*Frontend, []*Backend)) {
	if entry := store[name]; entry != nil {
		backends := entry.backendSlice()
		entry.frontends.Range(func(_ addrKey, lst frontendList) {
			if primary := lst.primary(); primary != nil {
				fn(lst.primary(), backends)
			}
		})
	}
}

func (store serviceStore) deleteBackends(name ServiceName, addrs []lb.L3n4Addr) {
	entry := store[name]
	if entry != nil {
		for _, addr := range addrs {
			entry.deleteBackend(addr)
		}
	}
}

// FIXME too much copying? Use the Hash() instead as the map key?
// Benchmark me.
type addrKey lb.L3n4Addr

func (a addrKey) Less(b addrKey) bool {
	return (lb.L3n4Addr)(a).Hash() < (lb.L3n4Addr)(b).Hash()
}

// serviceEntry contains a set of frontends and backends associated with a specific
// service.
//
// It is immutable when copied as value by using Hash Array Mapped Tries instead of
// the builtin hash maps. E.g. frontends is a struct that points to the root of the
// trie. If we pass serviceEntry by value, then we essentially pass forward a snapshot
// of the map at that point in time.
//
// This allows using the service entry as the event that is passed to service manager
// subscribers without worrying about the data being mutated underneath.
type serviceEntry struct {
	// metadata? creation time? handle that created it?
	name      ServiceName
	frontends *container.PMap[addrKey, frontendList]
	backends  *container.PMap[addrKey, Backend]
}

var _ Event = serviceEntry{}

func newServiceEntry(name ServiceName) *serviceEntry {
	return &serviceEntry{
		name:      name,
		frontends: container.NewPMap[addrKey, frontendList](),
		backends:  container.NewPMap[addrKey, Backend](),
	}
}

func (e serviceEntry) Name() ServiceName {
	return e.name
}

func (e serviceEntry) ForEachActiveFrontend(fn func(Frontend)) {
	e.frontends.Range(func(_ addrKey, l frontendList) {
		fn(*l.primary())
	})
}

func (e serviceEntry) ForEachBackend(fn func(Backend)) {
	e.backends.Range(func(_ addrKey, be Backend) {
		fn(be)
	})
}

func (e *serviceEntry) empty() bool {
	return e.frontends.Empty() && e.backends.Empty()
}

// upsertFrontend inserts or updates a frontend. Returns true and backends if this frontend is
// the primary for it's address.
func (e *serviceEntry) upsertFrontend(fe *Frontend) (isPrimary bool, backends []*Backend) {
	lst, _ := e.frontends.Get(addrKey(fe.Address))
	lst, isPrimary = lst.upsert(fe)
	e.frontends.Set(addrKey(fe.Address), lst)

	if isPrimary {
		return true, e.backendSlice()
	}
	return false, nil
}

// FIXME get rid of this and replace with Iter[Backend] etc.
func (e *serviceEntry) backendSlice() []*Backend {
	bes := []*Backend{}
	e.backends.Range(func(_ addrKey, be Backend) {
		bes = append(bes, &be)
	})
	return bes
}

// deleteFrontend deletes the given frontend.
// If primary changed, returns true and new primary (nil if none) and backends.
func (e *serviceEntry) deleteFrontend(addr lb.L3n4Addr, svcType lb.SVCType) (primary *Frontend, backends []*Backend) {
	var (
		wasPrimary bool
		frontends  frontendList
	)
	lst, _ := e.frontends.Get(addrKey(addr))
	lst, wasPrimary = lst.delete(svcType)
	frontends = lst
	e.frontends.Set(addrKey(addr), lst)

	if wasPrimary {
		primary = frontends.primary()
		backends = e.backendSlice() // Or Iter[*Backend]?
	}
	return
}

// upsertBackends inserts or updates backends
func (e *serviceEntry) upsertBackends(backends []*Backend) {
	fmt.Printf("serviceEntry[%v].upsertBackends %d\n", e.name, len(backends))
	for _, be := range backends {
		e.backends.Set(addrKey(be.L3n4Addr), *be)
	}
	fmt.Printf("serviceEntry[%v].upsertBackends done\n", e.name)
}

func (e *serviceEntry) deleteBackend(addr lb.L3n4Addr) {
	e.backends.Delete(addrKey(addr))
}
