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

	log "github.com/sirupsen/logrus"
)

const (
	MapName = "cilium_cidr_"
)

// CIDRMap refers to an LPM trie map at 'path'.
type CIDRMap struct {
	path     string
	Fd       int
	AddrSize int // max prefix length in bytes, 4 for IPv4, 16 for IPv6
}

// DeepCopy duplicates CIDRMap 'cm', but both copies refer to the same map.
func (cm *CIDRMap) DeepCopy() *CIDRMap {
	if cm == nil {
		return nil
	}

	return &CIDRMap{
		path:     cm.path,
		Fd:       cm.Fd,
		AddrSize: cm.AddrSize,
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

// AllowCIDR inserts an entry to 'cm' with key 'cidr'. Value is currently not
// used.
func (cm *CIDRMap) AllowCIDR(cidr net.IPNet) error {
	key := cm.cidrKeyInit(cidr)
	entry := [LPM_MAP_VALUE_SIZE]byte{}
	return bpf.UpdateElement(cm.Fd, unsafe.Pointer(&key), unsafe.Pointer(&entry), 0)
}

// CIDRExists returns true if 'cidr' exists in map 'cm'
func (cm *CIDRMap) CIDRExists(cidr net.IPNet) bool {
	key := cm.cidrKeyInit(cidr)
	var entry [LPM_MAP_VALUE_SIZE]byte
	return bpf.LookupElement(cm.Fd, unsafe.Pointer(&key), unsafe.Pointer(&entry)) == nil
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
// created, and 'false' if the map already existed.
func OpenMap(path string, prefixlen int) (*CIDRMap, bool, error) {
	if prefixlen <= 0 {
		return nil, false, fmt.Errorf("prefixlen must be > 0")
	}
	bytes := (prefixlen-1)/8 + 1
	fd, isNewMap, err := bpf.OpenOrCreateMap(
		path,
		bpf.BPF_MAP_TYPE_LPM_TRIE,
		uint32(unsafe.Sizeof(uint32(0))+uintptr(bytes)),
		uint32(LPM_MAP_VALUE_SIZE),
		MAX_KEYS,
		bpf.BPF_F_NO_PREALLOC,
	)

	if err != nil {
		log.Debugf("Kernel does not support LPM trie maps, using inline bpf tables instead.")
		return nil, false, err
	}

	m := &CIDRMap{path: path, Fd: fd, AddrSize: bytes}

	log.Debugf("Created LPM trie bpf map %s (fd: %d)", path, fd)

	return m, isNewMap, nil
}
