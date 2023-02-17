//go:build freebsd
// +build freebsd

package nv

// #cgo LDFLAGS: -lnv
// #include <sys/nv.h>
import "C"

import (
	"unsafe"
)

// Unmarshal decodes a FreeBSD name-value list (nv(9)) to a Go map
func Unmarshal(d []byte, out List) error {
	sz := C.ulong(len(d))
	dp := unsafe.Pointer(&d[0])
	nvl := C.nvlist_unpack(dp, sz, 0)

	return unmarshal(nvl, out)
}

func unmarshal(nvl *C.struct_nvlist, out List) error {
	// For debugging
	// C.nvlist_dump(nvl, C.int(os.Stdout.Fd()))

	var cookie unsafe.Pointer
	for {
		var typ C.int
		ckey := C.nvlist_next(nvl, &typ, &cookie)
		if ckey == nil {
			break
		}

		var sz C.size_t
		var value interface{}
		switch typ {
		case C.NV_TYPE_BINARY:
			v := C.nvlist_get_binary(nvl, ckey, &sz)
			value = C.GoBytes(v, C.int(sz))

		case C.NV_TYPE_BOOL:
			value = C.nvlist_get_bool(nvl, ckey)

		case C.NV_TYPE_NUMBER:
			v := C.nvlist_get_number(nvl, ckey)
			value = uint64(v)

		case C.NV_TYPE_NVLIST_ARRAY:
			items := []List{}

			nvlSubListsBuf := C.nvlist_get_nvlist_array(nvl, ckey, &sz)
			nvlSubLists := unsafe.Slice(nvlSubListsBuf, sz)
			for _, nvlSubList := range nvlSubLists {
				item := map[string]interface{}{}
				if err := unmarshal(nvlSubList, item); err != nil {
					return err
				}

				items = append(items, item)
			}

			value = items
		}

		name := C.GoString(ckey)
		out[name] = value
	}

	return nil
}
