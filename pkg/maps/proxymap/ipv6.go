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
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"
)

var Proxy6MapName = "cilium_proxy6"

// Proxy6Value
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type Proxy6Value struct {
	OrigDAddr      types.IPv6 `align:"orig_daddr"`
	OrigDPort      uint16     `align:"orig_dport"`
	Pad            uint16     `align:"pad"`
	SourceIdentity uint32     `align:"identity"`
	Lifetime       uint32     `align:"lifetime"`
}

// GetSourceIdentity returns the source identity
func (v *Proxy6Value) GetSourceIdentity() uint32 {
	return v.SourceIdentity
}

func (v *Proxy6Value) HostPort() string {
	portStr := strconv.FormatUint(uint64(v.OrigDPort), 10)
	return net.JoinHostPort(v.OrigDAddr.IP().String(), portStr)
}

var (
	// Proxy6Map represents the BPF map for IPv6 proxy
	Proxy6Map = bpf.NewMap(Proxy6MapName,
		bpf.MapTypeHash,
		int(unsafe.Sizeof(tuple.TupleKey6{})),
		int(unsafe.Sizeof(Proxy6Value{})),
		MaxEntries,
		0, 0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			k, v := tuple.TupleKey6{}, Proxy6Value{}

			if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
				return nil, nil, err
			}

			return k.ToNetwork(), v.ToNetwork(), nil
		}).WithNonPersistent()
)

func (v *Proxy6Value) GetValuePtr() unsafe.Pointer {
	return unsafe.Pointer(v)
}

// ToNetwork converts Proxy6Value to network byte order.
func (v *Proxy6Value) ToNetwork() *Proxy6Value {
	n := *v
	n.OrigDPort = byteorder.HostToNetwork(n.OrigDPort).(uint16)
	return &n
}

func (v *Proxy6Value) String() string {
	return fmt.Sprintf("%s:%d identity %d lifetime %d",
		v.OrigDAddr.IP().String(), v.OrigDPort, v.SourceIdentity, v.Lifetime)
}

func lookupEgress6(key *tuple.TupleKey6) (*Proxy6Value, error) {
	val, err := Proxy6Map.Lookup(key.ToNetwork())
	if err != nil {
		return nil, err
	}

	proxyVal := val.(*Proxy6Value)

	return proxyVal.ToNetwork(), nil
}

func gc6(time uint64) int {
	tsec := time / 1000000000
	deleted := 0

	if err := Proxy6Map.Open(); err != nil {
		return 0
	}

	var key, nextKey tuple.TupleKey6
	for doGc(unsafe.Pointer(&key), unsafe.Pointer(&nextKey), &deleted, uint32(tsec)) {
		key = nextKey
	}

	return deleted
}

// cleanupIPv6Redirects removes all redirects to a specific proxy port
func cleanupIPv6Redirects(proxyPort uint16) {
	if err := Proxy6Map.Open(); err != nil {
		return
	}

	dportNetworkOrder := byteorder.HostToNetwork(proxyPort).(uint16)

	var key, nextKey tuple.TupleKey6
	for {
		err := bpf.GetNextKey(Proxy6Map.GetFd(), unsafe.Pointer(&key), unsafe.Pointer(&nextKey))
		if err != nil {
			return
		}

		if nextKey.DestPort == dportNetworkOrder && nextKey.NextHeader == u8proto.U8proto(6) {
			log.Debugf("Cleaning up IPv6 proxymap, removing entry: %+v", nextKey)
			bpf.DeleteElement(Proxy6Map.GetFd(), unsafe.Pointer(&nextKey))
		}

		key = nextKey
	}
}
