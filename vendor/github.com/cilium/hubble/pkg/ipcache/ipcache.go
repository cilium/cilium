// Copyright 2019 Authors of Hubble
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

package ipcache

import (
	"fmt"
	"net"
	"sync"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/source"
)

// IPIdentity contains the data associated with an IP address
type IPIdentity struct {
	Identity  identity.NumericIdentity
	Namespace string
	PodName   string
}

type entry struct {
	CIDR     *net.IPNet
	Identity identity.NumericIdentity

	HostIP     net.IP
	EncryptKey uint8

	Namespace string
	PodName   string
}

// IPCache is a mirror of Cilium's ipcache
type IPCache struct {
	mutex sync.RWMutex
	// cache maps a cidr to its metadata
	cache map[string]entry
}

// New creates an new empty IPCache
func New() *IPCache {
	return &IPCache{
		mutex: sync.RWMutex{},
		cache: map[string]entry{},
	}
}

// Upsert updates or inserts an entry and returns true if the update was
// performed.
func (ipc *IPCache) Upsert(
	key string,
	id identity.NumericIdentity,
	hostIP net.IP,
	encryptKey uint8,
	namespace, podName string) bool {

	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()

	_, cidr, err := net.ParseCIDR(key)
	if err != nil {
		return false
	}

	ipc.cache[key] = entry{
		CIDR:       cidr,
		Identity:   id,
		HostIP:     hostIP,
		EncryptKey: encryptKey,
		Namespace:  namespace,
		PodName:    podName,
	}

	return true
}

// UpsertChecked performs an upsert and returns true if either an existing
// entry (with matching oldID and oldHostIP) was updated or if a new entry has
// been inserted. This is intended to be used with data obtained via Cilium
// monitor's `IPCacheNotification`
func (ipc *IPCache) UpsertChecked(
	key string,
	newID identity.NumericIdentity,
	oldID *identity.NumericIdentity,
	newHostIP, oldHostIP net.IP,
	encryptKey uint8,
	namespace, podName string) bool {

	_, cidr, err := net.ParseCIDR(key)
	if err != nil {
		// key is not a valid CIDR, it cannot be a valid entry
		return false
	}

	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()

	// if it is an update, ensure that we are not applying a stale update
	if oldEntry, ok := ipc.cache[key]; ok {
		if oldID == nil || oldEntry.Identity != *oldID ||
			!oldEntry.HostIP.Equal(oldHostIP) {
			return false
		}
	}

	// insert or replace entry
	ipc.cache[key] = entry{
		CIDR:       cidr,
		Identity:   newID,
		HostIP:     newHostIP,
		EncryptKey: encryptKey,
		Namespace:  namespace,
		PodName:    podName,
	}

	return true
}

// Delete performs a delete and returns true if an entry was deleted
func (ipc *IPCache) Delete(key string) bool {
	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()

	_, found := ipc.cache[key]
	delete(ipc.cache, key)
	return found
}

// InitializeFrom this IPCache instance from a list of entries obtained via
// Cilium API
func (ipc *IPCache) InitializeFrom(entries []*models.IPListEntry) error {
	cache := map[string]entry{}
	for _, e := range entries {
		if e == nil || e.Cidr == nil || e.Identity == nil {
			return fmt.Errorf("Received invalid ipcache entry from cilium")
		}

		var (
			id         = identity.NumericIdentity(*e.Identity)
			key        = *e.Cidr
			hostIP     = net.ParseIP(e.HostIP)
			encryptKey = uint8(e.EncryptKey)
		)

		_, cidr, err := net.ParseCIDR(key)
		if err != nil {
			return fmt.Errorf("IPCache entry key is not a CIDR: %s", err)
		}

		var ns, pod string
		if e.Metadata != nil && e.Metadata.Source == string(source.Kubernetes) {
			ns = e.Metadata.Namespace
			pod = e.Metadata.Name
		}

		cache[key] = entry{
			CIDR:       cidr,
			Identity:   id,
			HostIP:     hostIP,
			EncryptKey: encryptKey,
			Namespace:  ns,
			PodName:    pod,
		}
	}

	ipc.mutex.Lock()
	ipc.cache = cache
	ipc.mutex.Unlock()
	return nil
}

// GetIPIdentity returns the known information about a given IP
func (ipc *IPCache) GetIPIdentity(ip net.IP) (id IPIdentity, ok bool) {
	ipc.mutex.RLock()
	defer ipc.mutex.RUnlock()

	if e, ok := ipc.cache[ipToCIDR(ip).String()]; ok {
		return IPIdentity{Identity: e.Identity, Namespace: e.Namespace, PodName: e.PodName}, true
	}

	return IPIdentity{}, false
}

// ipToCIDR converts an IP into an equivalent full CIDR.
func ipToCIDR(ip net.IP) *net.IPNet {
	bits := net.IPv6len * 8
	if ip.To4() != nil {
		bits = net.IPv4len * 8
	}
	return &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(bits, bits),
	}
}
