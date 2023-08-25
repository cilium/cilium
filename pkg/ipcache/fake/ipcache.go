// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"net"

	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/source"
)

const (
	EventUpsert = "upsert"
	EventDelete = "delete"
)

type NodeEvent struct {
	event string
	ip    net.IP
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
	i.Events <- NodeEvent{EventUpsert, net.ParseIP(ip)}
	return false, nil
}

func (i *IPCache) Delete(IP string, source source.Source) bool {
	i.Events <- NodeEvent{EventDelete, net.ParseIP(IP)}
	return false
}
