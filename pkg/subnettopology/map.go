package subnettopology

import (
	"fmt"
	"sync"
	"unsafe"

	"net"
	"net/netip"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MaxEntries = 1024
	Name       = "cilium_subnet_map"
)

type Key struct {
	Prefixlen uint32 `align:"lpm_key"`
	ClusterID uint16 `align:"cluster_id"`
	Pad1      uint8  `align:"pad1"`
	Family    uint8  `align:"family"`
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP types.IPv6 `align:"$union0"`
}

func getStaticPrefixBits() uint32 {
	staticMatchSize := unsafe.Sizeof(Key{})
	staticMatchSize -= unsafe.Sizeof(Key{}.Prefixlen)
	staticMatchSize -= unsafe.Sizeof(Key{}.IP)
	return uint32(staticMatchSize) * 8
}

func (k Key) String() string {
	var (
		addr netip.Addr
		ok   bool
	)

	switch k.Family {
	case bpf.EndpointKeyIPv4:
		addr, ok = netip.AddrFromSlice(k.IP[:net.IPv4len])
		if !ok {
			return "<unknown>"
		}
	case bpf.EndpointKeyIPv6:
		addr = netip.AddrFrom16(k.IP)
	default:
		return "<unknown>"
	}

	prefixLen := int(k.Prefixlen - getStaticPrefixBits())
	clusterID := uint32(k.ClusterID)

	return cmtypes.PrefixClusterFrom(netip.PrefixFrom(addr, prefixLen), cmtypes.WithClusterID(clusterID)).String()
}

func (k *Key) New() bpf.MapKey { return &Key{} }

func (k Key) Prefix() netip.Prefix {
	var addr netip.Addr
	prefixLen := int(k.Prefixlen - getStaticPrefixBits())
	switch k.Family {
	case bpf.EndpointKeyIPv4:
		addr = netip.AddrFrom4(*(*[4]byte)(k.IP[:4]))
	case bpf.EndpointKeyIPv6:
		addr = netip.AddrFrom16(k.IP)
	}
	return netip.PrefixFrom(addr, prefixLen)
}

// getPrefixLen determines the length that should be set inside the Key so that
// the lookup prefix is correct in the BPF map key. The specified 'prefixBits'
// indicates the number of bits in the IP that must match to match the entry in
// the BPF ipcache.
func getPrefixLen(prefixBits int) uint32 {
	return getStaticPrefixBits() + uint32(prefixBits)
}

// NewKey returns an Key based on the provided IP address, mask, and ClusterID.
// The address family is automatically detected
func NewKey(ip net.IP, mask net.IPMask, clusterID uint16) Key {
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

	result.ClusterID = clusterID

	return result
}

type Value struct {
	Identity uint32 `align:"identity"`
}

func (v *Value) String() string {
	return fmt.Sprintf("Identity: %d", v.Identity)
}

func (v *Value) New() bpf.MapValue { return &Value{} }

func NewValue(identity uint32) Value {
	return Value{
		Identity: identity,
	}
}

type Map struct {
	bpf.Map
}

func newSubnetMap(name string) *bpf.Map {
	m := bpf.NewMap(
		name,
		ebpf.LPMTrie,
		&Key{},
		&Value{},
		MaxEntries,
		unix.BPF_F_NO_PREALLOC)
	return m
}

// NewMap instantiates a Map.
func NewSubnetMap(registry *metrics.Registry, name string) *Map {
	return &Map{
		Map: *newSubnetMap(name).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(name)),
	}
}

var (
	subnetMap *Map
	once      = &sync.Once{}
)

func SubnetMap(registry *metrics.Registry) *Map {
	once.Do(func() {
		subnetMap = NewSubnetMap(registry, Name)
	})
	return subnetMap
}
