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

package cidrmap

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logfields"

	log "github.com/sirupsen/logrus"
)

const (
	MapName = "cilium_cidr_"
)

// CIDRMap refers to an LPM trie map at 'path'.
type CIDRMap struct {
	path      string
	Fd        int
	AddrSize  int // max prefix length in bytes, 4 for IPv4, 16 for IPv6
	Prefixlen uint32
}

// DeepCopy duplicates CIDRMap 'cm', but both copies refer to the same map.
func (cm *CIDRMap) DeepCopy() *CIDRMap {
	if cm == nil {
		return nil
	}

	return &CIDRMap{
		path:      cm.path,
		Fd:        cm.Fd,
		AddrSize:  cm.AddrSize,
		Prefixlen: cm.Prefixlen,
	}
}

const (
	MAX_KEYS           = 1024
	LPM_MAP_VALUE_SIZE = 1
)

type cidrKey struct {
	Prefixlen uint32
	Net       [16]byte
}

func (cm *CIDRMap) cidrKeyInit(cidr net.IPNet) (key cidrKey) {
	ones, _ := cidr.Mask.Size()
	key.Prefixlen = uint32(ones)
	// IPv4 address can be represented by 16 byte slice in 'cidr.IP',
	// in which case the address is at the end of the slice.
	copy(key.Net[:], cidr.IP[len(cidr.IP)-cm.AddrSize:len(cidr.IP)])
	return
}

func (cm *CIDRMap) keyCidrInit(key cidrKey) (cidr net.IPNet) {
	cidr.Mask = net.CIDRMask(int(key.Prefixlen), cm.AddrSize*8)
	cidr.IP = make(net.IP, cm.AddrSize)
	copy(cidr.IP[len(cidr.IP)-cm.AddrSize:len(cidr.IP)], key.Net[:])
	return
}

// InsertCIDR inserts an entry to 'cm' with key 'cidr'. Value is currently not
// used.
func (cm *CIDRMap) InsertCIDR(cidr net.IPNet) error {
	key := cm.cidrKeyInit(cidr)
	entry := [LPM_MAP_VALUE_SIZE]byte{}
	if cm.Prefixlen != 0 && cm.Prefixlen != key.Prefixlen {
		return fmt.Errorf("Unable to update element with different prefixlen than map!")
	}
	return bpf.UpdateElement(cm.Fd, unsafe.Pointer(&key), unsafe.Pointer(&entry), 0)
}

// DeleteCIDR deletes an entry from 'cm' with key 'cidr'.
func (cm *CIDRMap) DeleteCIDR(cidr net.IPNet) error {
	key := cm.cidrKeyInit(cidr)
	if cm.Prefixlen != 0 && cm.Prefixlen != key.Prefixlen {
		return fmt.Errorf("Unable to delete element with different prefixlen than map!")
	}
	return bpf.DeleteElement(cm.Fd, unsafe.Pointer(&key))
}

// CIDRExists returns true if 'cidr' exists in map 'cm'
func (cm *CIDRMap) CIDRExists(cidr net.IPNet) bool {
	key := cm.cidrKeyInit(cidr)
	var entry [LPM_MAP_VALUE_SIZE]byte
	return bpf.LookupElement(cm.Fd, unsafe.Pointer(&key), unsafe.Pointer(&entry)) == nil
}

// CIDRNext returns next CIDR entry in map 'cm'
func (cm *CIDRMap) CIDRNext(cidr *net.IPNet) *net.IPNet {
	var key, keyNext cidrKey
	if cidr != nil {
		key = cm.cidrKeyInit(*cidr)
	}
	err := bpf.GetNextKey(cm.Fd, unsafe.Pointer(&key), unsafe.Pointer(&keyNext))
	if err != nil {
		return nil
	}
	out := cm.keyCidrInit(keyNext)
	return &out
}

// CIDRDump walks map 'cm' and dumps all CIDR entries
func (cm *CIDRMap) CIDRDump(to []string) []string {
	var key, keyNext *net.IPNet
	for {
		keyNext = cm.CIDRNext(key)
		if keyNext == nil {
			return to
		}
		key = keyNext
		to = append(to, key.String())
	}
}

// String returns the path of the map.
func (cm *CIDRMap) String() string {
	if cm == nil {
		return ""
	}
	return cm.path
}

// Close closes the FD of the given CIDRMap
func (cm *CIDRMap) Close() error {
	if cm == nil {
		return nil
	}
	return bpf.ObjClose(cm.Fd)
}

// OpenMap opens a new CIDRMap. 'bool' returns 'true' if the map was
// created, and 'false' if the map already existed. prefixdyn denotes
// whether element's prefixlen can vary and we thus need to use a LPM
// trie instead of hash table.
func OpenMap(path string, prefixlen int, prefixdyn bool) (*CIDRMap, bool, error) {
	return OpenMapElems(path, prefixlen, prefixdyn, MAX_KEYS)
}

// OpenMapElems is the same as OpenMap only with defined maxelem as argument.
func OpenMapElems(path string, prefixlen int, prefixdyn bool, maxelem uint32) (*CIDRMap, bool, error) {
	var typeMap = bpf.BPF_MAP_TYPE_LPM_TRIE
	var prefix = 0

	if prefixdyn == false {
		typeMap = bpf.BPF_MAP_TYPE_HASH
		prefix = prefixlen
	}
	if prefixlen <= 0 {
		return nil, false, fmt.Errorf("prefixlen must be > 0")
	}
	bytes := (prefixlen-1)/8 + 1
	fd, isNewMap, err := bpf.OpenOrCreateMap(
		path,
		typeMap,
		uint32(unsafe.Sizeof(uint32(0))+uintptr(bytes)),
		uint32(LPM_MAP_VALUE_SIZE),
		maxelem,
		bpf.BPF_F_NO_PREALLOC,
	)

	if err != nil {
		log.Debug("Kernel does not support CIDR maps, using inline bpf tables instead.")
		return nil, false, err
	}

	m := &CIDRMap{path: path, Fd: fd, AddrSize: bytes, Prefixlen: uint32(prefix)}

	log.WithFields(log.Fields{
		logfields.Path: path,
		"fd":           fd,
	}).Debug("Created CIDR map")

	return m, isNewMap, nil
}
