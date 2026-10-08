// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/source"
)

const (
	EventUpsert = "upsert"
	EventDelete = "delete"
)

type NodeEvent struct {
	event string
	ip    netip.Addr
}

type IPCache struct {
	eventsEnabled bool
	Events        chan NodeEvent
}

func NewIPCache(events bool) *IPCache {
	return &IPCache{
		eventsEnabled: events,
		Events:        make(chan NodeEvent, 1024),
	}
}

func (i *IPCache) Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (bool, error) {
	addr, _ := netip.ParseAddr(ip)
	i.Events <- NodeEvent{EventUpsert, addr}
	return false, nil
}

func (i *IPCache) Delete(IP string, source source.Source) bool {
	addr, _ := netip.ParseAddr(IP)
	i.Events <- NodeEvent{EventDelete, addr}
	return false
}
