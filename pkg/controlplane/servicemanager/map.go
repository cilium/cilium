package servicemanager

import (
	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

type serviceWithBackends struct {
	*Service
	backends []*Backend
}

func servicePriority(s *Service) int {
	if s.Type == loadbalancer.SVCTypeLocalRedirect {
		return 1
	}
	return 0
}

type serviceList struct {
	services []serviceWithBackends
}

func newServiceList() *serviceList { return &serviceList{} }

func (l *serviceList) lookup(typ loadbalancer.SVCType) (*Service, []*Backend) {
	for _, s := range l.services {
		if s.Type == typ {
			return s.Service, s.backends
		}
	}
	return nil, nil
}

func (l *serviceList) upsert(id ServiceID, svc *Service, backends []*Backend) {
	for i, other := range l.services {
		if svc.Type == other.Type {
			l.services[i] = serviceWithBackends{svc, backends}
		}
	}
	l.services = append(l.services, serviceWithBackends{svc, backends})
	slices.SortFunc(l.services, func(a, b serviceWithBackends) bool {
		return servicePriority(a.Service) < servicePriority(b.Service)
	})
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

type serviceStore struct {
	services map[loadbalancer.L3n4Addr]*serviceList
}

func (s *serviceStore) delete(id ServiceID) {
	if list := s.services[id.Frontend]; list != nil {
		list.delete(id.Type)
		if list.empty() {
			delete(s.services, id.Frontend)
		}
	}
}

func (s *serviceStore) lookup(id ServiceID) (*Service, []*Backend) {
	if list := s.services[id.Frontend]; list != nil {
		return list.lookup(id.Type)
	}
	return nil, nil
}

func (s *serviceStore) upsert(id ServiceID, svc *Service, backends []*Backend) {
	list := s.services[id.Frontend]
	if list == nil {
		list = newServiceList()
		s.services[id.Frontend] = list
	}
	list.upsert(id, svc, backends)
}
