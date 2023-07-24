// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/types"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-ipcache")

const (
	// MaxEntries is the maximum number of keys that can be present in the
	// RemoteEndpointMap.
	MaxEntries = 512000

	// Name is the canonical name for the IPCache map on the filesystem.
	Name = "cilium_ipcache"

	// maxPrefixLengths is an approximation of how many different CIDR
	// prefix lengths may be supported by the BPF datapath without causing
	// BPF code generation to exceed the verifier instruction limit.
	// It applies to Linux versions that lack support for LPM, ie < v4.11.
	//
	// This is based upon the defines in bpf/ep_config.h, which in turn
	// are derived by building the bpf/ directory and running the script
	// test/bpf/verifier-test.sh, then adjusting the number of unique
	// prefix lengths until the script passes.
	maxPrefixLengths6 = 4
	maxPrefixLengths4 = 18
)

// Key implements the bpf.MapKey interface.
//
// Must be in sync with struct ipcache_key in <bpf/lib/maps.h>
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Key struct {
	Prefixlen uint32 `align:"lpm_key"`
	Pad1      uint16 `align:"pad1"`
	Pad2      uint8  `align:"pad2"`
	Family    uint8  `align:"family"`
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP types.IPv6 `align:"$union0"`
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k Key) NewValue() bpf.MapValue { return &RemoteEndpointInfo{} }

func getStaticPrefixBits() uint32 {
	staticMatchSize := unsafe.Sizeof(Key{})
	staticMatchSize -= unsafe.Sizeof(Key{}.Prefixlen)
	staticMatchSize -= unsafe.Sizeof(Key{}.IP)
	return uint32(staticMatchSize) * 8
}

func (k Key) String() string {
	prefixLen := k.Prefixlen - getStaticPrefixBits()
	switch k.Family {
	case bpf.EndpointKeyIPv4:
		ipStr := net.IP(k.IP[:net.IPv4len]).String()
		return fmt.Sprintf("%s/%d", ipStr, prefixLen)
	case bpf.EndpointKeyIPv6:
		ipStr := k.IP.String()
		return fmt.Sprintf("%s/%d", ipStr, prefixLen)
	}
	return "<unknown>"
}

func (k Key) IPNet() *net.IPNet {
	cidr := &net.IPNet{}
	prefixLen := k.Prefixlen - getStaticPrefixBits()
	switch k.Family {
	case bpf.EndpointKeyIPv4:
		cidr.IP = net.IP(k.IP[:net.IPv4len])
		cidr.Mask = net.CIDRMask(int(prefixLen), 32)
	case bpf.EndpointKeyIPv6:
		cidr.IP = net.IP(k.IP[:net.IPv6len])
		cidr.Mask = net.CIDRMask(int(prefixLen), 128)
	}
	return cidr
}

// getPrefixLen determines the length that should be set inside the Key so that
// the lookup prefix is correct in the BPF map key. The specified 'prefixBits'
// indicates the number of bits in the IP that must match to match the entry in
// the BPF ipcache.
func getPrefixLen(prefixBits int) uint32 {
	return getStaticPrefixBits() + uint32(prefixBits)
}

// NewKey returns an Key based on the provided IP address and mask. The address
// family is automatically detected
func NewKey(ip net.IP, mask net.IPMask) Key {
	result := Key{}

	ones, _ := mask.Size()
	if ip4 := ip.To4(); ip4 != nil {
		if mask == nil {
			ones = net.IPv4len * 8
		}
		result.Prefixlen = getPrefixLen(ones)
		result.Family = bpf.EndpointKeyIPv4
		copy(result.IP[:], ip4)
	} else {
		if mask == nil {
			ones = net.IPv6len * 8
		}
		result.Prefixlen = getPrefixLen(ones)
		result.Family = bpf.EndpointKeyIPv6
		copy(result.IP[:], ip)
	}

	return result
}

// RemoteEndpointInfo implements the bpf.MapValue interface. It contains the
// security identity of a remote endpoint.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type RemoteEndpointInfo struct {
	SecurityIdentity uint32     `align:"sec_label"`
	TunnelEndpoint   types.IPv4 `align:"tunnel_endpoint"`
	_                uint16
	Key              uint8 `align:"key"`
}

func (v *RemoteEndpointInfo) String() string {
	return fmt.Sprintf("identity=%d encryptkey=%d tunnelendpoint=%s",
		v.SecurityIdentity, v.Key, v.TunnelEndpoint)
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *RemoteEndpointInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// Map represents an IPCache BPF map.
type Map struct {
	bpf.Map

	// detectDeleteSupport is used to initialize 'supportsDelete' the first
	// time that a delete is issued from the datapath.
	detectDeleteSupport sync.Once

	// deleteSupport is set to 'true' initially, then is updated to set
	// whether the underlying kernel supports delete operations on the map
	// the first time that supportsDelete() is called.
	deleteSupport bool
}

func newIPCacheMap(name string) *bpf.Map {
	return bpf.NewMap(
		name,
		bpf.MapTypeLPMTrie,
		&Key{},
		int(unsafe.Sizeof(Key{})),
		&RemoteEndpointInfo{},
		int(unsafe.Sizeof(RemoteEndpointInfo{})),
		MaxEntries,
		bpf.BPF_F_NO_PREALLOC, 0,
		bpf.ConvertKeyValue)
}

// NewMap instantiates a Map.
func NewMap(name string) *Map {
	return &Map{
		Map:           *newIPCacheMap(name).WithCache().WithPressureMetric(),
		deleteSupport: true,
	}
}

// delete removes a key from the ipcache BPF map, and returns whether the
// kernel supports the delete operation (true) or not (false), and any error
// that may have occurred while attempting to delete the entry.
//
// If "overwrite" is true, then if delete is not supported the entry's value
// will be overwritten with zeroes to signify that it's an invalid entry.
func (m *Map) delete(k bpf.MapKey, overwrite bool) (bool, error) {
	err := m.Delete(k)
	var errno unix.Errno
	if ok := errors.As(err, &errno); ok && errno == unix.ENOSYS {
		if overwrite {
			// Older kernels do not support deletion of LPM map entries so zero out
			// the entry instead of attempting a deletion
			return false, m.Update(k, &RemoteEndpointInfo{})
		}
		return false, nil
	}
	return true, err
}

// DeleteWithOverwrite removes a key from the ipcache BPF map.
// If delete is not supported, the entry's value will be overwritten with
// zeroes to signify that it's an invalid entry.
func (m *Map) DeleteWithOverwrite(k bpf.MapKey) error {
	_, err := m.delete(k, true)
	return err
}

// GetMaxPrefixLengths determines how many unique prefix lengths are supported
// simultaneously based on the underlying BPF map type in use.
func (m *Map) GetMaxPrefixLengths() (ipv6, ipv4 int) {
	if BackedByLPM() {
		return net.IPv6len*8 + 1, net.IPv4len*8 + 1
	}
	return maxPrefixLengths6, maxPrefixLengths4
}

func (m *Map) supportsDelete() bool {
	m.detectDeleteSupport.Do(func() {
		// Create a separate map for the probing since this map may not have been created yet.
		probeMap := newIPCacheMap(m.Name() + "_probe")
		err := probeMap.CreateUnpinned()
		if err != nil {
			log.WithError(err).Warn("Failed to open IPCache map for feature probing, assuming delete and dump unsupported")
			m.deleteSupport = false
			return
		}
		defer probeMap.Close()

		// Entry is invalid because IPCache needs a family specified.
		invalidEntry := &Key{}
		err = probeMap.Delete(invalidEntry)
		var errno unix.Errno
		if ok := errors.As(err, &errno); ok && errno == unix.ENOSYS {
			m.deleteSupport = false
		} else {
			m.deleteSupport = true
		}
		log.Debugf("Detected IPCache delete operation support: %t", m.deleteSupport)

		// Detect dump support
		err = probeMap.Dump(map[string][]string{})
		dumpSupport := err == nil
		log.Debugf("Detected IPCache dump operation support: %t", dumpSupport)

		// In addition to delete support, ability to dump the map is
		// also required in order to run the garbage collector which
		// will iterate over the map and delete entries.
		m.deleteSupport = m.deleteSupport && dumpSupport

		if !m.deleteSupport {
			log.Infof("Periodic IPCache map swap will occur due to lack of kernel support for LPM delete operation. Upgrade to Linux 4.15 or higher to avoid this.")
		}
	})
	return m.deleteSupport
}

// SupportsDelete determines whether the underlying kernel map type supports
// the delete operation.
func SupportsDelete() bool {
	return IPCache.supportsDelete()
}

// BackedByLPM returns true if the IPCache is backed by a proper LPM
// implementation (provided by Linux kernels 4.11 or later), false otherwise.
func BackedByLPM() bool {
	return IPCache.MapType == bpf.MapTypeLPMTrie
}

var (
	// IPCache is a mapping of all endpoint IPs in the cluster which this
	// Cilium agent is a part of to their corresponding security identities.
	// It is a singleton; there is only one such map per agent.
	IPCache = NewMap(Name)
)

// Reopen attempts to close and re-open the IPCache map at the standard path
// on the filesystem.
func Reopen() error {
	return IPCache.Map.Reopen()
}
