package lbmap

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// SkipLB4MapName is the name of the IPv4 BPF map that stores entries to skip LB for.
	SkipLB4MapName = "cilium_skip_lb4"

	// SkipLB6MapName is the name of the IPv6 BPF map that stores entries to skip LB for.
	SkipLB6MapName = "cilium_skip_lb6"

	// SkipLB4MapSize is the maximum number of entries in the skip LB BPF map.
	// TODO: expose as a config option
	SkipLB4MapSize = 1000

	// SkipLB6MapSize is the maximum number of entries in the skip LB BPF map.
	SkipLB6MapSize = 1000
)

// SkipLBMap provides access to the eBPF map that stores entries for which load-balancing is skipped.
type SkipLBMap interface {
	AddLB4(netnsCookie uint64, ip net.IP, port uint16) error
	AddLB6(netnsCookie uint64, ip net.IP, port uint16) error
}

func NewSkipLBMap() (SkipLBMap, error) {
	skipLBMap := &skipLBMap{}

	if option.Config.EnableLocalRedirectPolicy {
		if option.Config.EnableIPv4 {
			skipLBMap.bpfMap4 = ebpf.NewMap(&ebpf.MapSpec{
				Name:       SkipLB4MapName,
				Type:       ebpf.LRUHash,
				KeySize:    uint32(unsafe.Sizeof(SkipLB4Key{})),
				ValueSize:  uint32(unsafe.Sizeof(SkipLB4Value{})),
				MaxEntries: SkipLB4MapSize,
				Flags:      0,
				Pinning:    ebpf.PinByName},
			)
			if err := skipLBMap.bpfMap4.Close(); err != nil {
				log.Infof("debug-aditi failed to close skip map")
			}
			if err := skipLBMap.bpfMap4.OpenOrCreate(); err != nil {
				return nil, fmt.Errorf("failed to open or create %s: %v", SkipLB4MapName, err)
			}
		}
		if option.Config.EnableIPv6 {
			if option.Config.EnableLocalRedirectPolicy {
				skipLBMap.bpfMap6 = ebpf.NewMap(&ebpf.MapSpec{
					Name:       SkipLB6MapName,
					Type:       ebpf.LRUHash,
					KeySize:    uint32(unsafe.Sizeof(SkipLB6Key{})),
					ValueSize:  uint32(unsafe.Sizeof(SkipLB6Value{})),
					MaxEntries: SkipLB6MapSize,
					Flags:      0,
					Pinning:    ebpf.PinByName},
				)
				if err := skipLBMap.bpfMap6.OpenOrCreate(); err != nil {
					return nil, fmt.Errorf("failed to open or create %s: %v", SkipLB6MapName, err)
				}
			}
		}
	}

	return skipLBMap, nil
}

// AddLB4 adds the given tuple to skip LB for to the BPF v4 map.
func (m *skipLBMap) AddLB4(netnsCookie uint64, ip net.IP, port uint16) error {
	return m.bpfMap4.Update(
		NewSkipLB4Key(netnsCookie, ip.To4(), port),
		&SkipLB4Value{}, 0)
}

// AddLB6 adds the given tuple to skip LB for to the BPF v6 map.
func (m *skipLBMap) AddLB6(netnsCookie uint64, ip net.IP, port uint16) error {
	return m.bpfMap6.Update(
		NewSkipLB6Key(netnsCookie, ip.To16(), port),
		&SkipLB6Value{}, 0)
}

// SkipLB4Key is the tuple with netns cookie, address and port and used as key in
// the skip LB4 map.
type SkipLB4Key struct {
	NetnsCookie uint64     `align:"cookie"`
	Address     types.IPv4 `align:"address"`
	Port        uint16     `align:"port"`
	Pad         int16      `align:"pad"`
}

type SkipLB4Value struct {
	Pad uint8 `align:"pad"`
}

// NewSkipLB4Key creates the SkipLB4Key
func NewSkipLB4Key(netnsCookie uint64, address net.IP, port uint16) *SkipLB4Key {
	key := SkipLB4Key{
		NetnsCookie: byteorder.NetworkToHost64(netnsCookie),
		Port:        port,
	}
	copy(key.Address[:], address.To4())

	return &key
}

func (k *SkipLB4Key) New() bpf.MapKey { return &SkipLB4Key{} }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *SkipLB4Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human-readable string format.
func (k *SkipLB4Key) String() string {
	return fmt.Sprintf("[%d]:%d, %d", k.NetnsCookie, k.Address, k.Port)
}

func (v *SkipLB4Value) New() bpf.MapValue { return &SkipLB4Value{} }

// String converts the value into a human-readable string format.
func (v *SkipLB4Value) String() string {
	return ""
}

// SkipLB6Key is the tuple with netns cookie, address and port and used as key in
// the skip LB6 map.
type SkipLB6Key struct {
	NetnsCookie uint64     `align:"cookie"`
	Address     types.IPv6 `align:"address"`
	Port        uint16     `align:"port"`
	Pad         int16      `align:"pad"`
}

type SkipLB6Value struct {
	Pad uint8 `align:"pad"`
}

// NewSkipLB6Key creates the SkipLB6Key
func NewSkipLB6Key(netnsCookie uint64, address net.IP, port uint16) *SkipLB6Key {
	key := SkipLB6Key{
		NetnsCookie: netnsCookie,
		Port:        port,
	}
	copy(key.Address[:], address.To16())

	return &key
}

func (k *SkipLB6Key) New() bpf.MapKey { return &SkipLB6Key{} }

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *SkipLB6Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *SkipLB6Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human-readable string format.
func (k *SkipLB6Key) String() string {
	return fmt.Sprintf("[%d]:%d, %d", k.NetnsCookie, k.Address, k.Port)
}

func (v *SkipLB6Value) New() bpf.MapValue { return &SkipLB6Value{} }

// String converts the value into a human-readable string format.
func (v *SkipLB6Value) String() string {
	return ""
}

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k *SkipLB6Key) NewValue() bpf.MapValue { return &SkipLB6Value{} }

type skipLBMap struct {
	bpfMap4 *ebpf.Map
	bpfMap6 *ebpf.Map
}
