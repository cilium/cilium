//go:build freebsd
// +build freebsd

package nv

/*
#cgo LDFLAGS: -lnv
#include <stdlib.h>
#include <sys/nv.h>

// For sizeof(*struct nvlist)
typedef struct nvlist *nvlist_ptr;
*/
import "C"

import (
	"unsafe"
)

// Marshal encodes a Go map to a FreeBSD name-value list (nv(9))
func Marshal(m List) (*byte, int, error) {
	nvl, err := marshal(m)
	if err != nil {
		return nil, -1, err
	}

	// For debugging
	// C.nvlist_dump(nvl, C.int(os.Stdout.Fd()))

	var sz C.size_t
	buf := C.nvlist_pack(nvl, &sz)

	return (*byte)(buf), int(sz), nil
}

func marshal(m List) (nvl *C.struct_nvlist, err error) {
	nvl = C.nvlist_create(0)

	for key, value := range m {
		ckey := C.CString(key)

		switch value := value.(type) {
		case bool:
			C.nvlist_add_bool(nvl, ckey, C.bool(value))

		case uint64:
			C.nvlist_add_number(nvl, ckey, C.ulong(value))

		case []byte:
			sz := len(value)
			ptr := C.CBytes(value)
			C.nvlist_add_binary(nvl, ckey, ptr, C.size_t(sz))
			C.free(ptr)

		case []List:
			sz := len(value)
			buf := C.malloc(C.size_t(C.sizeof_nvlist_ptr * sz))
			items := (*[1<<30 - 1]*C.struct_nvlist)(buf)

			for i, val := range value {
				if items[i], err = marshal(val); err != nil {
					C.free(unsafe.Pointer(ckey))
					return nil, err
				}
			}

			C.nvlist_add_nvlist_array(nvl, ckey, (**C.struct_nvlist)(buf), C.size_t(sz))
			C.free(buf)
		}

		C.free(unsafe.Pointer(ckey))
	}

	return
}
