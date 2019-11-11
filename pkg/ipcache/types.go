// Copyright 2019 Authors of Cilium

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
	"net"

	"github.com/cilium/cilium/pkg/source"
)

// IPCacheInterface is an interface hiding the implementation of `IPCache`.
type IPCacheInterface interface {

	// Upsert inserts the information about the specified IP into the IPCache.
	// Returns false if the ip is not owned by the specified source in
	// `newIdentity`.
	Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *K8sMetadata, newIdentity Identity) bool

	// Delete removes the provided IP-to-security-identity mapping from the IPCache.
	Delete(IP string, source source.Source)

	// LookupByIP returns the corresponding security identity that endpoint IP maps
	// to within the provided IPCache, as well as if the corresponding entry exists
	// in the IPCache.
	LookupByIP(IP string) (Identity, bool)

	// NotifyListenersGC runs `OnIPIdentityCacheGC` for all listeners for this
	// IPCache.
	NotifyListenersGC()
}
