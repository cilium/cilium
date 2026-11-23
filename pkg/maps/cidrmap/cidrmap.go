// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidrmap

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/registry"
)

const (
	MapName    = "cilium_cidr_"
	MaxEntries = 16384
)

// CIDRMap refers to an LPM trie map at 'path'.
type CIDRMap struct {
	logger    *slog.Logger
	path      string
	m         *bpf.Map
	AddrSize  int // max prefix length in bytes, 4 for IPv4, 16 for IPv6
	Prefixlen uint32

	// PrefixIsDynamic determines whether it's valid for entries to have
	// a prefix length that is not equal to the Prefixlen above
	PrefixIsDynamic bool
}

const (
	LPM_MAP_VALUE_SIZE = 1
)

type cidrKey4 struct {
	Prefixlen uint32
	Net       [net.IPv4len]byte
}

func (k *cidrKey4) String() string {
	return fmt.Sprintf("%d:%x", k.Prefixlen, k.Net)
}

func (k *cidrKey4) New() bpf.MapKey {
	return &cidrKey4{}
}

type cidrKey6 struct {
	Prefixlen uint32
	Net       [net.IPv6len]byte
}

func (k *cidrKey6) String() string {
	return fmt.Sprintf("%d:%x", k.Prefixlen, k.Net)
}

func (k *cidrKey6) New() bpf.MapKey {
	return &cidrKey6{}
}

func newCIDRKey(addrSize int) (bpf.MapKey, error) {
	switch addrSize {
	case net.IPv4len:
		return &cidrKey4{}, nil
	case net.IPv6len:
		return &cidrKey6{}, nil
	default:
		return nil, fmt.Errorf("unsupported CIDR address size %d", addrSize)
	}
}

func (cm *CIDRMap) cidrKeyInit(cidr net.IPNet) bpf.MapKey {
	ones, _ := cidr.Mask.Size()
	switch cm.AddrSize {
	case net.IPv4len:
		key := &cidrKey4{Prefixlen: uint32(ones)}
		copy(key.Net[:], cidr.IP[len(cidr.IP)-cm.AddrSize:])
		return key
	case net.IPv6len:
		key := &cidrKey6{Prefixlen: uint32(ones)}
		copy(key.Net[:], cidr.IP[len(cidr.IP)-cm.AddrSize:])
		return key
	default:
		panic(fmt.Sprintf("unsupported CIDR address size %d", cm.AddrSize))
	}
}

func (cm *CIDRMap) keyCidrInit(key bpf.MapKey) (cidr net.IPNet) {
	var prefixlen uint32
	cidr.IP = make(net.IP, cm.AddrSize)

	switch key := key.(type) {
	case *cidrKey4:
		prefixlen = key.Prefixlen
		copy(cidr.IP, key.Net[:])
	case *cidrKey6:
		prefixlen = key.Prefixlen
		copy(cidr.IP, key.Net[:])
	default:
		panic(fmt.Sprintf("unsupported CIDR key type %T", key))
	}

	cidr.Mask = net.CIDRMask(int(prefixlen), cm.AddrSize*8)
	return
}

// checkPrefixlen checks whether it's valid to manipulate elements in the map
// with the specified key. If it's unsupported, it returns an error.
func (cm *CIDRMap) checkPrefixlen(key bpf.MapKey, operation string) error {
	var prefixlen uint32
	switch key := key.(type) {
	case *cidrKey4:
		prefixlen = key.Prefixlen
	case *cidrKey6:
		prefixlen = key.Prefixlen
	default:
		return fmt.Errorf("unsupported CIDR key type %T", key)
	}

	if cm.Prefixlen != 0 &&
		((cm.PrefixIsDynamic && cm.Prefixlen < prefixlen) ||
			(!cm.PrefixIsDynamic && cm.Prefixlen != prefixlen)) {
		return fmt.Errorf("Unable to %s element with dynamic prefix length cm.Prefixlen=%d key.Prefixlen=%d",
			operation, cm.Prefixlen, prefixlen)
	}
	return nil
}

type cidrValue [LPM_MAP_VALUE_SIZE]byte

func (v *cidrValue) String() string {
	return fmt.Sprintf("%x", *v)
}

func (v *cidrValue) New() bpf.MapValue {
	return &cidrValue{}
}

// InsertCIDR inserts an entry to 'cm' with key 'cidr'. Value is currently not
// used.
func (cm *CIDRMap) InsertCIDR(cidr net.IPNet) error {
	key := cm.cidrKeyInit(cidr)
	entry := cidrValue{}
	if err := cm.checkPrefixlen(key, "update"); err != nil {
		return err
	}
	cm.logger.Debug(
		"Inserting CIDR entry",
		logfields.Path, cm.path,
		logfields.CIDR, cidr,
	)
	return cm.m.Update(key, &entry)
}

// DeleteCIDR deletes an entry from 'cm' with key 'cidr'.
func (cm *CIDRMap) DeleteCIDR(cidr net.IPNet) error {
	key := cm.cidrKeyInit(cidr)
	if err := cm.checkPrefixlen(key, "delete"); err != nil {
		return err
	}
	cm.logger.Debug(
		"Removing CIDR entry",
		logfields.Path, cm.path,
		logfields.CIDR, cidr,
	)
	return cm.m.Delete(key)
}

// CIDRExists returns true if 'cidr' exists in map 'cm'
func (cm *CIDRMap) CIDRExists(cidr net.IPNet) bool {
	key := cm.cidrKeyInit(cidr)
	var entry cidrValue
	return cm.m.LookupInto(key, &entry) == nil
}

// CIDRNext returns next CIDR entry in map 'cm'
func (cm *CIDRMap) CIDRNext(cidr *net.IPNet) *net.IPNet {
	var key bpf.MapKey
	if cidr != nil {
		key = cm.cidrKeyInit(*cidr)
	}
	keyNext, err := newCIDRKey(cm.AddrSize)
	if err != nil {
		return nil
	}
	if err := cm.m.NextKey(key, keyNext); err != nil {
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

// OpenMapFromRegistry opens or creates a CIDR map using its finalized
// specification from the map registry.
func OpenMapFromRegistry(
	reg *registry.MapRegistry,
	logger *slog.Logger,
	name string,
	prefixlen int,
	prefixdyn bool,
) (*CIDRMap, error) {
	prefix := 0
	if !prefixdyn {
		prefix = prefixlen
	}
	if prefixlen <= 0 {
		return nil, fmt.Errorf("prefixlen must be > 0")
	}

	bytes := (prefixlen-1)/8 + 1
	key, err := newCIDRKey(bytes)
	if err != nil {
		return nil, err
	}
	m, err := bpf.NewMapFromRegistry(reg, name, key, &cidrValue{})
	if err != nil {
		return nil, fmt.Errorf("create map from registry: %w", err)
	}
	if err := m.OpenOrCreate(); err != nil {
		return nil, err
	}
	pinPath, err := m.Path()
	if err != nil {
		logger.Warn(
			"Failed to get CIDR map pinPath",
			logfields.Error, err,
		)
		return nil, err
	}

	logger.Debug(
		"Created CIDR map",
		logfields.Path, pinPath,
		logfields.BPFMapFD, m.FD(),
		logfields.LPM, prefixdyn,
	)

	return &CIDRMap{
		logger:          logger,
		path:            pinPath,
		m:               m,
		AddrSize:        bytes,
		Prefixlen:       uint32(prefix),
		PrefixIsDynamic: prefixdyn,
	}, nil
}
