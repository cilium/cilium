// Copyright 2016-2017 Authors of Cilium
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

package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"unsafe"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
)

type Proxy6Key struct {
	SAddr   types.IPv6
	DPort   uint16
	SPort   uint16
	Nexthdr uint8
	Pad     uint8
}

func (k *Proxy6Key) HostPort() string {
	portStr := strconv.FormatUint(uint64(k.SPort), 10)
	return net.JoinHostPort(k.SAddr.IP().String(), portStr)
}

type Proxy6Value struct {
	OrigDAddr      types.IPv6
	OrigDPort      uint16
	Lifetime       uint16
	SourceIdentity uint32
}

func (p *Proxy6Value) HostPort() string {
	portStr := strconv.FormatUint(uint64(p.OrigDPort), 10)
	return net.JoinHostPort(p.OrigDAddr.IP().String(), portStr)
}

var (
	proxy6Map = bpf.NewMap("cilium_proxy6",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(Proxy6Key{})),
		int(unsafe.Sizeof(Proxy6Value{})),
		8192, 0).WithNonPersistent()
)

func init() {
	bpf.OpenAfterMount(proxy6Map)
}

func (k Proxy6Key) NewValue() bpf.MapValue {
	return &Proxy6Value{}
}

func (k *Proxy6Key) GetKeyPtr() unsafe.Pointer {
	return unsafe.Pointer(k)
}

func (k *Proxy6Key) String() string {
	return fmt.Sprintf("%s (%d) => %d", k.HostPort(), k.Nexthdr, k.DPort)
}

// ToNetwork converts Proxy6Key ports to network byte order.
func (k *Proxy6Key) ToNetwork() *Proxy6Key {
	n := *k
	n.SPort = byteorder.HostToNetwork(n.SPort).(uint16)
	n.DPort = byteorder.HostToNetwork(n.DPort).(uint16)
	return &n
}

func (v *Proxy6Value) GetValuePtr() unsafe.Pointer {
	return unsafe.Pointer(v)
}

// ToNetwork converts Proxy6Value to network byte order.
func (p *Proxy6Value) ToNetwork() *Proxy6Value {
	n := *p
	n.OrigDPort = byteorder.HostToNetwork(n.OrigDPort).(uint16)
	return &n
}

func (v *Proxy6Value) String() string {
	return fmt.Sprintf("%s:%d", v.OrigDAddr.IP().String(), v.OrigDPort)
}

func LookupEgress6(key *Proxy6Key) (*Proxy6Value, error) {
	val, err := proxy6Map.Lookup(key.ToNetwork())
	if err != nil {
		return nil, err
	}

	proxyVal := val.(*Proxy6Value)

	return proxyVal.ToNetwork(), nil
}

func proxy6DumpParser(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
	keyBuf := bytes.NewBuffer(key)
	valueBuf := bytes.NewBuffer(value)
	k := Proxy6Key{}
	v := Proxy6Value{}

	if err := binary.Read(keyBuf, byteorder.Native, &k); err != nil {
		return nil, nil, fmt.Errorf("Unable to convert key: %s\n", err)
	}

	if err := binary.Read(valueBuf, byteorder.Native, &v); err != nil {
		return nil, nil, fmt.Errorf("Unable to convert key: %s\n", err)
	}

	return k.ToNetwork(), v.ToNetwork(), nil
}

func Dump6(cb bpf.DumpCallback) error {
	if err := proxy6Map.Open(); err != nil {
		return err
	}

	return proxy6Map.Dump(proxy6DumpParser, cb)
}

func doGc6(interval uint16, key unsafe.Pointer, nextKey unsafe.Pointer, deleted *int) bool {
	var entry Proxy6Value

	err := bpf.GetNextKey(proxy6Map.GetFd(), key, nextKey)
	if err != nil {
		return false
	}

	err = bpf.LookupElement(proxy6Map.GetFd(), nextKey, unsafe.Pointer(&entry))
	if err != nil {
		return false
	}

	if entry.Lifetime <= interval {
		bpf.DeleteElement(proxy6Map.GetFd(), nextKey)
		(*deleted)++
	} else {
		entry.Lifetime -= interval
		bpf.UpdateElement(proxy6Map.GetFd(), nextKey, unsafe.Pointer(&entry), 0)
	}

	return true
}

func GC6() int {
	deleted := 0

	if err := proxy6Map.Open(); err != nil {
		return 0
	}

	var key, nextKey Proxy6Key
	for doGc(10, unsafe.Pointer(&key), unsafe.Pointer(&nextKey), &deleted) {
		key = nextKey
	}

	return deleted
}
