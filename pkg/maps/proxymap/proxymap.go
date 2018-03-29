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
)

const (
	MaxEntries = 524288
)

// ProxyMapKey is the generic type for Proxy6Key or Proxy4Key
type ProxyMapKey interface{}

type ProxyMapValue interface {
	GetSourceIdentity() uint32
	HostPort() string
	String() string
}

// Delete removes a proxymap map entry
func Delete(key ProxyMapKey) error {
	switch keyValue := key.(type) {
	case Proxy4Key:
		return Proxy4Map.Delete(&keyValue)
	case Proxy6Key:
		return Proxy6Map.Delete(&keyValue)
	}

	return fmt.Errorf("Unknown proxymap key type: %+v", key)
}

// Lookup looks up an entry in the proxymap
func Lookup(key ProxyMapKey) (ProxyMapValue, error) {
	switch keyValue := key.(type) {
	case Proxy4Key:
		val, err := lookupEgress4(&keyValue)
		if err != nil {
			return nil, fmt.Errorf("unable to find IPv4 proxy entry for %s: %s", key, err)
		}

		return val, nil

	case Proxy6Key:
		val, err := lookupEgress6(&keyValue)
		if err != nil {
			return nil, fmt.Errorf("unable to find IPv6 proxy entry for %s: %s", key, err)
		}

		return val, nil
	}

	return nil, fmt.Errorf("Unknown proxymap key type: %+v", key)
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
