// Copyright 2018 Authors of Cilium
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

package proxymap

import (
	"fmt"
	"math"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/tuple"
)

const (
	MaxEntries = 524288
)

// ProxyMapKey is the generic type for tuple.TupleKey6 or tuple.TupleKey4
type ProxyMapKey interface{}

type ProxyMapValue interface {
	GetSourceIdentity() uint32
	HostPort() string
	String() string
}

// Delete removes a proxymap map entry
func Delete(key ProxyMapKey) error {
	switch keyValue := key.(type) {
	case tuple.TupleKey4:
		return Proxy4Map.Delete(&keyValue)
	case tuple.TupleKey6:
		return Proxy6Map.Delete(&keyValue)
	}

	return fmt.Errorf("unknown proxymap key type: %T", key)
}

// Lookup looks up an entry in the proxymap
func Lookup(key ProxyMapKey) (ProxyMapValue, error) {
	switch keyValue := key.(type) {
	case tuple.TupleKey4:
		val, err := lookupEgress4(&keyValue)
		if err != nil {
			return nil, fmt.Errorf("unable to find IPv4 proxy entry for %s: %s", &keyValue, err)
		}

		return val, nil

	case tuple.TupleKey6:
		val, err := lookupEgress6(&keyValue)
		if err != nil {
			return nil, fmt.Errorf("unable to find IPv6 proxy entry for %s: %s", &keyValue, err)
		}

		return val, nil
	}

	return nil, fmt.Errorf("unknown proxymap key type: %T", key)
}

// CleanupOnRedirectClose cleans up the proxymap after a redirect has been
// closed. It will remove all proxymap entries to the proxy port.
func CleanupOnRedirectClose(p uint16) {
	cleanupIPv4Redirects(p)
	cleanupIPv6Redirects(p)
}

// GC garbage collects entries whose lifetime has expired. Returns the number
// of entries removed.
func GC() int {
	time, _ := bpf.GetMtime()
	return gc(time) + gc6(time)
}

// Flush flushes all proxymap entries, returns the number of entries removed.
func Flush() int {
	return gc(math.MaxUint64) + gc6(math.MaxUint64)
}
