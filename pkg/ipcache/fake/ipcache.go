// Copyright 2020 Authors of Cilium
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

// +build !privileged_tests

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

func (i *IPCache) Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (bool, bool) {
	i.Events <- NodeEvent{EventUpsert, net.ParseIP(ip)}
	return true, false
}

func (i *IPCache) Delete(IP string, source source.Source) bool {
	i.Events <- NodeEvent{EventDelete, net.ParseIP(IP)}
	return false
}
