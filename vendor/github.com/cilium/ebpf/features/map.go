package features

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

func init() {
	mc.mapTypes = make(map[ebpf.MapType]error)
}

var (
	mc mapCache
)

type mapCache struct {
	sync.Mutex
	mapTypes map[ebpf.MapType]error
}

func createMapTypeAttr(mt ebpf.MapType) *sys.MapCreateAttr {
	var (
		keySize        uint32 = 4
		valueSize      uint32 = 4
		maxEntries     uint32 = 1
		innerMapFd     uint32
		flags          uint32
		btfKeyTypeID   uint32
		btfValueTypeID uint32
		btfFd          uint32
	)

	// switch on map types to generate correct MapCreateAttr
	switch mt {
	case ebpf.StackTrace:
		// valueSize needs to be sizeof(uint64)
		valueSize = 8
	case ebpf.LPMTrie:
		// keySize and valueSize need to be sizeof(struct{u32 + u8}) + 1 + padding = 8
		// BPF_F_NO_PREALLOC needs to be set
		// checked at allocation time for lpm_trie maps
		keySize = 8
		valueSize = 8
		flags = unix.BPF_F_NO_PREALLOC
	case ebpf.ArrayOfMaps, ebpf.HashOfMaps:
		// assign invalid innerMapFd to pass validation check
		// will return EBADF
		innerMapFd = ^uint32(0)
	case ebpf.CGroupStorage, ebpf.PerCPUCGroupStorage:
		// keySize needs to be sizeof(struct{u32 + u64}) = 12 (+ padding = 16)
		// by using unsafe.Sizeof(int) we are making sure that this works on 32bit and 64bit archs
		// checked at allocation time
		var align int
		keySize = uint32(8 + unsafe.Sizeof(align))
		maxEntries = 0
	case ebpf.Queue, ebpf.Stack:
		// keySize needs to be 0, see alloc_check for queue and stack maps
		keySize = 0
	case ebpf.RingBuf:
		// keySize and valueSize need to be 0
		// maxEntries needs to be power of 2 and PAGE_ALIGNED
		// checked at allocation time
		keySize = 0
		valueSize = 0
		maxEntries = uint32(os.Getpagesize())
	case ebpf.SkStorage, ebpf.InodeStorage, ebpf.TaskStorage:
		// maxEntries needs to be 0
		// BPF_F_NO_PREALLOC needs to be set
		// btf* fields need to be set
		// see alloc_check for local_storage map types
		maxEntries = 0
		flags = unix.BPF_F_NO_PREALLOC
		btfKeyTypeID = 1   // BTF_KIND_INT
		btfValueTypeID = 3 // BTF_KIND_ARRAY
		btfFd = ^uint32(0)
	}

	return &sys.MapCreateAttr{
		MapType:        sys.MapType(mt),
		KeySize:        keySize,
		ValueSize:      valueSize,
		MaxEntries:     maxEntries,
		InnerMapFd:     innerMapFd,
		MapFlags:       flags,
		BtfKeyTypeId:   btfKeyTypeID,
		BtfValueTypeId: btfValueTypeID,
		BtfFd:          btfFd,
	}
}

// HaveMapType probes the running kernel for the availability of the specified map type.
//
// See the package documentation for the meaning of the error return value.
func HaveMapType(mt ebpf.MapType) error {
	if err := validateMaptype(mt); err != nil {
		return err
	}

	return haveMapType(mt)
}

func validateMaptype(mt ebpf.MapType) error {
	if mt > mt.Max() {
		return os.ErrInvalid
	}

	if mt == ebpf.StructOpsMap {
		// A probe for StructOpsMap has vmlinux BTF requirements we currently
		// cannot meet. Once we figure out how to add a working probe in this
		// package, we can remove this check.
		return errors.New("a probe for MapType StructOpsMap isn't implemented")
	}

	return nil
}

func haveMapType(mt ebpf.MapType) error {
	mc.Lock()
	defer mc.Unlock()
	err, ok := mc.mapTypes[mt]
	if ok {
		return err
	}

	fd, err := sys.MapCreate(createMapTypeAttr(mt))

	switch {
	// For nested and storage map types we accept EBADF as indicator that these maps are supported
	case errors.Is(err, unix.EBADF):
		if isMapOfMaps(mt) || isStorageMap(mt) {
			err = nil
		}

	// EINVAL occurs when attempting to create a map with an unknown type.
	// E2BIG occurs when MapCreateAttr contains non-zero bytes past the end
	// of the struct known by the running kernel, meaning the kernel is too old
	// to support the given map type.
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.E2BIG):
		err = ebpf.ErrNotSupported

	// EPERM is kept as-is and is not converted or wrapped.
	case errors.Is(err, unix.EPERM):
		break

	// Wrap unexpected errors.
	case err != nil:
		err = fmt.Errorf("unexpected error during feature probe: %w", err)

	default:
		fd.Close()
	}

	mc.mapTypes[mt] = err

	return err
}

func isMapOfMaps(mt ebpf.MapType) bool {
	switch mt {
	case ebpf.ArrayOfMaps, ebpf.HashOfMaps:
		return true
	}
	return false
}

func isStorageMap(mt ebpf.MapType) bool {
	switch mt {
	case ebpf.SkStorage, ebpf.InodeStorage, ebpf.TaskStorage:
		return true
	}

	return false
}
