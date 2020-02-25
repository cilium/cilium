// Copyright 2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package servicecache

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	pb "github.com/cilium/hubble/api/v1/flow"

	"github.com/cilium/cilium/api/v1/models"
)

// ServiceCache is a cache of existing services.
type ServiceCache struct {
	mu    sync.RWMutex
	cache map[string]*entry
}

// New creates a new empty ServiceCache.
func New() *ServiceCache {
	return &ServiceCache{
		cache: map[string]*entry{},
	}
}

type entry struct {
	ID           int64
	Name         string
	Namespace    string
	FrontendIP   net.IP
	FrontendPort uint16
}

// GetServiceByAddr retrieves a service from the cache given its frontend IP
// and port. If the service was found in the cache, ok is true.
func (svcc *ServiceCache) GetServiceByAddr(ip net.IP, port uint16) (service pb.Service, ok bool) {
	svcc.mu.RLock()
	defer svcc.mu.RUnlock()

	if e, ok := svcc.cache[genAddrKey(ip, port)]; ok {
		return pb.Service{
			Name:      e.Name,
			Namespace: e.Namespace,
		}, true
	}
	return pb.Service{}, false
}

// InitializeFrom initializes the cache with the given list of services.
func (svcc *ServiceCache) InitializeFrom(entries []*models.Service) error {
	cache := map[string]*entry{}
	for _, e := range entries {
		if e == nil || e.Spec == nil || e.Spec.FrontendAddress == nil || e.Spec.Flags == nil {
			return fmt.Errorf("received invalid service entry from cilium: %+v", e)
		}
		frontendIP := net.ParseIP(e.Spec.FrontendAddress.IP)
		if frontendIP == nil {
			return fmt.Errorf("received service entry with invalid address: %s", e.Spec.FrontendAddress.IP)
		}
		frontendPort := e.Spec.FrontendAddress.Port
		ce := &entry{
			ID:           e.Spec.ID,
			Name:         e.Spec.Flags.Name,
			Namespace:    e.Spec.Flags.Namespace,
			FrontendIP:   frontendIP,
			FrontendPort: frontendPort,
		}
		cache[genAddrKey(frontendIP, frontendPort)] = ce
		cache[genIDKey(e.Spec.ID)] = ce
	}
	svcc.mu.Lock()
	svcc.cache = cache
	svcc.mu.Unlock()
	return nil
}

// Upsert updates or inserts a cache entry and returns true if the update was
// performed.
func (svcc *ServiceCache) Upsert(id int64, name, typ, ns string, frontendIP net.IP, frontendPort uint16) bool {
	svcc.mu.Lock()
	defer svcc.mu.Unlock()

	idKey := genIDKey(id)
	// the ID of a service should never change and should be unique
	// thus, it acts as the reference key when unsure which entry to update
	if old, exist := svcc.cache[idKey]; exist {
		// make sure to remove the old addr reference
		delete(svcc.cache, genAddrKey(old.FrontendIP, old.FrontendPort))
	}
	e := &entry{
		ID:           id,
		Name:         name,
		Namespace:    ns,
		FrontendIP:   frontendIP,
		FrontendPort: frontendPort,
	}
	svcc.cache[genAddrKey(frontendIP, frontendPort)] = e
	svcc.cache[idKey] = e
	return true
}

// DeleteByID removes the cache entry identified by the given id. It returns
// true if an entry was deleted.
func (svcc *ServiceCache) DeleteByID(id int64) bool {
	svcc.mu.Lock()
	defer svcc.mu.Unlock()

	idKey := genIDKey(id)
	e, found := svcc.cache[idKey]
	if found {
		delete(svcc.cache, idKey)
		delete(svcc.cache, genAddrKey(e.FrontendIP, e.FrontendPort))
	}
	return found
}

// DeleteByAddr removes the cache entry identified by the given service
// frontend ip and port. It returns true if an entry was deleted.
func (svcc *ServiceCache) DeleteByAddr(ip net.IP, port uint16) bool {
	svcc.mu.Lock()
	defer svcc.mu.Unlock()

	addrKey := genAddrKey(ip, port)
	e, found := svcc.cache[addrKey]
	if found {
		delete(svcc.cache, addrKey)
		delete(svcc.cache, genIDKey(e.ID))
	}
	return found
}

// genAddrKey generates an address key in the form addr:<ip:port>.
func genAddrKey(ip net.IP, port uint16) string {
	var ipStr string
	if len(ip) > 0 { // an empty IP is usually represented as <nil>, we prefer having an empty string
		ipStr = ip.String()
	}
	return fmt.Sprintf("addr:%s", net.JoinHostPort(ipStr, strconv.FormatUint(uint64(port), 10)))
}

// genIDKey generates an id key in the form id:<id>.
func genIDKey(id int64) string {
	return fmt.Sprintf("id:%d", id)
}
