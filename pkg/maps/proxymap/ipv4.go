// Copyright 2016-2018 Authors of Cilium
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
	"net"
	"strconv"
	"unsafe"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log           = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-proxy")
	Proxy4MapName = "cilium_proxy4"
)

type Proxy4Key struct {
	SAddr   types.IPv4 `align:"saddr"`
	DPort   uint16     `align:"dport"`
	SPort   uint16     `align:"sport"`
	Nexthdr uint8      `align:"nexthdr"`
	Pad     uint8      `align:"pad"`
}

// HostPort returns host port for provided proxy key
func (k *Proxy4Key) HostPort() string {
	portStr := strconv.FormatUint(uint64(k.SPort), 10)
	return net.JoinHostPort(k.SAddr.IP().String(), portStr)
}

type Proxy4Value struct {
	OrigDAddr      types.IPv4 `align:"orig_daddr"`
	OrigDPort      uint16     `align:"orig_dport"`
	Pad            uint16     `align:"pad"`
	SourceIdentity uint32     `align:"identity"`
	Lifetime       uint32     `align:"lifetime"`
}

// GetSourceIdentity returns the source identity
func (v *Proxy4Value) GetSourceIdentity() uint32 {
	return v.SourceIdentity
}

func (v *Proxy4Value) HostPort() string {
	portStr := strconv.FormatUint(uint64(v.OrigDPort), 10)
	return net.JoinHostPort(v.OrigDAddr.IP().String(), portStr)
}

var (
	// Proxy4Map represents the BPF map for IPv4 proxy
	Proxy4Map = bpf.NewMap(Proxy4MapName,
		bpf.MapTypeHash,
		int(unsafe.Sizeof(Proxy4Key{})),
		int(unsafe.Sizeof(Proxy4Value{})),
		MaxEntries,
		0, 0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			k, v := Proxy4Key{}, Proxy4Value{}

			if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
				return nil, nil, err
			}

			return k.ToNetwork(), v.ToNetwork(), nil
		}).WithNonPersistent()
)

func (k Proxy4Key) NewValue() bpf.MapValue {
	return &Proxy4Value{}
}

func (k *Proxy4Key) GetKeyPtr() unsafe.Pointer {
	return unsafe.Pointer(k)
}

func (k *Proxy4Key) String() string {
	return fmt.Sprintf("%s (%d) => %d", k.HostPort(), k.Nexthdr, k.DPort)
}

// ToNetwork converts Proxy4Key ports to network byte order.
func (k *Proxy4Key) ToNetwork() *Proxy4Key {
	n := *k
	n.SPort = byteorder.HostToNetwork(n.SPort).(uint16)
	n.DPort = byteorder.HostToNetwork(n.DPort).(uint16)
	return &n
}

func (v *Proxy4Value) GetValuePtr() unsafe.Pointer {
	return unsafe.Pointer(v)
}

// ToNetwork converts Proxy4Value to network byte order.
func (v *Proxy4Value) ToNetwork() *Proxy4Value {
	n := *v
	n.OrigDPort = byteorder.HostToNetwork(n.OrigDPort).(uint16)
	return &n
}

func (v *Proxy4Value) String() string {
	return fmt.Sprintf("%s:%d identity %d lifetime %d",
		v.OrigDAddr.IP().String(), v.OrigDPort, v.SourceIdentity, v.Lifetime)
}

func lookupEgress4(key *Proxy4Key) (*Proxy4Value, error) {
	val, err := Proxy4Map.Lookup(key.ToNetwork())
	if err != nil {
		return nil, err
	}

	proxyVal := val.(*Proxy4Value)

	return proxyVal.ToNetwork(), nil
}

func doGc(key unsafe.Pointer, nextKey unsafe.Pointer, deleted *int, time uint32) bool {
	var entry Proxy4Value

	err := bpf.GetNextKey(Proxy4Map.GetFd(), key, nextKey)
	if err != nil {
		return false
	}

	err = bpf.LookupElement(Proxy4Map.GetFd(), nextKey, unsafe.Pointer(&entry))
	if err != nil {
		return false
	}

	if entry.Lifetime < time {
		bpf.DeleteElement(Proxy4Map.GetFd(), nextKey)
		(*deleted)++
	}

	return true
}

func gc(time uint64) int {
	tsec := time / 1000000000
	deleted := 0

	if err := Proxy4Map.Open(); err != nil {
		return 0
	}

	var key, nextKey Proxy4Key
	for doGc(unsafe.Pointer(&key), unsafe.Pointer(&nextKey), &deleted, uint32(tsec)) {
		key = nextKey
	}

	return deleted
}

// cleanupIPv4Redirects removes all redirects to a specific proxy port
func cleanupIPv4Redirects(proxyPort uint16) {
	if err := Proxy4Map.Open(); err != nil {
		return
	}

	dportNetworkOrder := byteorder.HostToNetwork(proxyPort).(uint16)

	var key, nextKey Proxy4Key
	for {
		err := bpf.GetNextKey(Proxy4Map.GetFd(), unsafe.Pointer(&key), unsafe.Pointer(&nextKey))
		if err != nil {
			return
		}

		if nextKey.DPort == dportNetworkOrder && nextKey.Nexthdr == uint8(6) {
			log.Debugf("Cleaning up IPv4 proxymap, removing entry: %+v", nextKey)
			bpf.DeleteElement(Proxy4Map.GetFd(), unsafe.Pointer(&nextKey))
		}

		key = nextKey
	}
}
