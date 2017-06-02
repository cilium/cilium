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

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
)

type Proxy4Key struct {
	SAddr   types.IPv4
	DPort   uint16
	SPort   uint16
	Nexthdr uint8
}

func (k *Proxy4Key) HostPort() string {
	portStr := strconv.FormatUint(uint64(k.SPort), 10)
	return net.JoinHostPort(k.SAddr.IP().String(), portStr)
}

type Proxy4Value struct {
	OrigDAddr types.IPv4
	OrigDPort uint16
	Lifetime  uint16
}

func (p *Proxy4Value) HostPort() string {
	portStr := strconv.FormatUint(uint64(p.OrigDPort), 10)
	return net.JoinHostPort(p.OrigDAddr.IP().String(), portStr)
}

var (
	proxy4Map = bpf.NewMap("cilium_proxy4",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(Proxy4Key{})),
		int(unsafe.Sizeof(Proxy4Value{})),
		8192, 0)
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

func (k *Proxy4Key) Convert() *Proxy4Key {
	n := *k
	n.SPort = common.Swab16(n.SPort)
	n.DPort = common.Swab16(n.DPort)
	return &n
}

func (v *Proxy4Value) GetValuePtr() unsafe.Pointer {
	return unsafe.Pointer(v)
}

func (k *Proxy4Value) Convert() *Proxy4Value {
	n := *k
	n.OrigDPort = common.Swab16(n.OrigDPort)
	return &n
}

func (v *Proxy4Value) String() string {
	return fmt.Sprintf("%s:%d", v.OrigDAddr.IP().String(), v.OrigDPort)
}

func LookupEgress4(key *Proxy4Key) (*Proxy4Value, error) {
	val, err := proxy4Map.Lookup(key.Convert())
	if err != nil {
		return nil, err
	}

	proxyVal := val.(*Proxy4Value)

	return proxyVal.Convert(), nil
}

func proxy4DumpParser(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
	keyBuf := bytes.NewBuffer(key)
	valueBuf := bytes.NewBuffer(value)
	k := Proxy4Key{}
	v := Proxy4Value{}

	if err := binary.Read(keyBuf, binary.LittleEndian, &k); err != nil {
		return nil, nil, fmt.Errorf("Unable to convert key: %s\n", err)
	}

	if err := binary.Read(valueBuf, binary.LittleEndian, &v); err != nil {
		return nil, nil, fmt.Errorf("Unable to convert key: %s\n", err)
	}

	return k.Convert(), v.Convert(), nil
}

func Dump(cb bpf.DumpCallback) error {
	if err := proxy4Map.Open(); err != nil {
		return err
	}

	return proxy4Map.Dump(proxy4DumpParser, cb)
}

func doGc(interval uint16, key unsafe.Pointer, nextKey unsafe.Pointer, deleted *int) bool {
	var entry Proxy4Value

	err := bpf.GetNextKey(proxy4Map.GetFd(), key, nextKey)
	if err != nil {
		return false
	}

	err = bpf.LookupElement(proxy4Map.GetFd(), nextKey, unsafe.Pointer(&entry))
	if err != nil {
		return false
	}

	if entry.Lifetime <= interval {
		bpf.DeleteElement(proxy4Map.GetFd(), nextKey)
		(*deleted)++
	} else {
		entry.Lifetime -= interval
		bpf.UpdateElement(proxy4Map.GetFd(), nextKey, unsafe.Pointer(&entry), 0)
	}

	return true
}

func GC() int {
	deleted := 0

	if err := proxy4Map.Open(); err != nil {
		return 0
	}

	var key, nextKey Proxy4Key
	for doGc(10, unsafe.Pointer(&key), unsafe.Pointer(&nextKey), &deleted) {
		key = nextKey
	}

	return deleted
}
