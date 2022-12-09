package servicemanager

import (
	"golang.org/x/exp/slices"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

type frontAndBack struct {
	*Frontend
	backends []*Backend
}

var typeToPriority = map[loadbalancer.SVCType]int{}

func frontendPriority(s *Frontend) int {
	if s.Type == loadbalancer.SVCTypeLocalRedirect {
		return 1
	}
	return 0
}

type serviceList struct {
	services []frontAndBack
}

func newFrontendList() *serviceList { return &serviceList{} }

func (l *serviceList) lookup(typ loadbalancer.SVCType) (*Frontend, []*Backend) {
	for _, s := range l.services {
		if s.Type == typ {
			return s.Frontend, s.backends
		}
	}
	return nil, nil
}

func (l *serviceList) upsert(id FrontendID, svc *Frontend, backends []*Backend) bool {
	for i, other := range l.services {
		if svc.Type == other.Type {
			l.services[i] = frontAndBack{svc, backends}
		}
	}
	l.services = append(l.services, frontAndBack{svc, backends})
	slices.SortFunc(l.services, func(a, b frontAndBack) bool {
		return frontendPriority(a.Frontend) < frontendPriority(b.Frontend)
	})
	return l.services[0].Type == id.Type
}

func (l *serviceList) delete(typ loadbalancer.SVCType) {
	for i, info := range l.services {
		if info.Type == typ {
			l.services = slices.Delete(l.services, i, i+1)
			return
		}
	}
}

func (l *serviceList) empty() bool {
	return len(l.services) == 0
}

type serviceStore map[loadbalancer.L3n4Addr]*serviceList

func (store serviceStore) delete(id FrontendID) {
	if list := store[id.Address]; list != nil {
		list.delete(id.Type)
		if list.empty() {
			delete(store, id.Address)
		}
	}
}

func (store serviceStore) lookupByAddr(addr loadbalancer.L3n4Addr) (*Frontend, []*Backend) {
	if list := store[addr]; list != nil {
		return list.services[0].Frontend, list.services[0].backends
	}
	return nil, nil
}

// upsert creates or updates the frontend. Returns true if this frontend is the
// primary frontend.
func (store serviceStore) upsert(id FrontendID, svc *Frontend, backends []*Backend) bool {
	list := store[id.Address]
	if list == nil {
		list = newFrontendList()
		store[id.Address] = list
	}
	return list.upsert(id, svc, backends)
}
