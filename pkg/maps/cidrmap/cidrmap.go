// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidrmap

import (
	"fmt"
	"net"
	"path"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-cidr")

const (
	MapName    = "cilium_cidr_"
	MaxEntries = 16384
)

// CIDRMap refers to an LPM trie map at 'path'.
type CIDRMap struct {
	path      string
	m         *ebpf.Map
	AddrSize  int // max prefix length in bytes, 4 for IPv4, 16 for IPv6
	Prefixlen uint32

	// PrefixIsDynamic determines whether it's valid for entries to have
	// a prefix length that is not equal to the Prefixlen above
	PrefixIsDynamic bool
}

const (
	LPM_MAP_VALUE_SIZE = 1
)

type cidrKey struct {
	Prefixlen uint32

	// v4 LPM maps have 8-byte key sizes even though the 20-byte cidrKey is used
	// for map ops. This hack relies on passing unsafe.Pointers to the cidrKey so
	// the kernel only accesses Prefixlen (4 bytes) and the first 4 bytes of Net.
	// v4 net.IPNets are packed into those 4 first bytes.
	Net [16]byte
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

// checkPrefixlen checks whether it's valid to manipulate elements in the map
// with the specified key. If it's unsupported, it returns an error.
func (cm *CIDRMap) checkPrefixlen(key *cidrKey, operation string) error {
	if cm.Prefixlen != 0 &&
		((cm.PrefixIsDynamic && cm.Prefixlen < key.Prefixlen) ||
			(!cm.PrefixIsDynamic && cm.Prefixlen != key.Prefixlen)) {
		return fmt.Errorf("Unable to %s element with dynamic prefix length cm.Prefixlen=%d key.Prefixlen=%d",
			operation, cm.Prefixlen, key.Prefixlen)
	}
	return nil
}

// InsertCIDR inserts an entry to 'cm' with key 'cidr'. Value is currently not
// used.
func (cm *CIDRMap) InsertCIDR(cidr net.IPNet) error {
	key := cm.cidrKeyInit(cidr)
	entry := [LPM_MAP_VALUE_SIZE]byte{}
	if err := cm.checkPrefixlen(&key, "update"); err != nil {
		return err
	}
	log.WithField(logfields.Path, cm.path).Debugf("Inserting CIDR entry %s", cidr.String())
	return cm.m.Update(unsafe.Pointer(&key), unsafe.Pointer(&entry), ebpf.UpdateAny)
}

// DeleteCIDR deletes an entry from 'cm' with key 'cidr'.
func (cm *CIDRMap) DeleteCIDR(cidr net.IPNet) error {
	key := cm.cidrKeyInit(cidr)
	if err := cm.checkPrefixlen(&key, "delete"); err != nil {
		return err
	}
	log.WithField(logfields.Path, cm.path).Debugf("Removing CIDR entry %s", cidr.String())
	return cm.m.Delete(unsafe.Pointer(&key))
}

// CIDRExists returns true if 'cidr' exists in map 'cm'
func (cm *CIDRMap) CIDRExists(cidr net.IPNet) bool {
	key := cm.cidrKeyInit(cidr)
	var entry [LPM_MAP_VALUE_SIZE]byte
	return cm.m.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&entry)) == nil
}

// CIDRNext returns next CIDR entry in map 'cm'
func (cm *CIDRMap) CIDRNext(cidr *net.IPNet) *net.IPNet {
	var key, keyNext cidrKey
	if cidr != nil {
		key = cm.cidrKeyInit(*cidr)
	}
	if err := cm.m.NextKey(unsafe.Pointer(&key), unsafe.Pointer(&keyNext)); err != nil {
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
	return cm.m.Close()
}

// OpenMapElems is the same as OpenMap only with defined maxelem as argument.
func OpenMapElems(pinPath string, prefixlen int, prefixdyn bool, maxelem uint32) (*CIDRMap, error) {
	mapType := ebpf.LPMTrie
	prefix := 0

	if !prefixdyn {
		mapType = ebpf.Hash
		prefix = prefixlen
	}
	if prefixlen <= 0 {
		return nil, fmt.Errorf("prefixlen must be > 0")
	}
	bytes := (prefixlen-1)/8 + 1
	m, err := bpf.OpenOrCreateMap(&ebpf.MapSpec{
		Name:       path.Base(pinPath),
		Type:       mapType,
		KeySize:    uint32(unsafe.Sizeof(uint32(0)) + uintptr(bytes)),
		ValueSize:  uint32(LPM_MAP_VALUE_SIZE),
		MaxEntries: maxelem,
		Flags:      bpf.BPF_F_NO_PREALLOC,
		Pinning:    ebpf.PinByName,
	}, path.Dir(pinPath))

	if err != nil {
		scopedLog := log.WithError(err).WithField(logfields.Path, pinPath)
		scopedLog.Warning("Failed to create CIDR map")
		return nil, err
	}

	log.WithFields(logrus.Fields{
		logfields.Path: pinPath,
		"fd":           m.FD(),
		"LPM":          m.Type() == ebpf.LPMTrie,
	}).Debug("Created CIDR map")

	return &CIDRMap{
		path:            pinPath,
		m:               m,
		AddrSize:        bytes,
		Prefixlen:       uint32(prefix),
		PrefixIsDynamic: prefixdyn,
	}, nil
}
