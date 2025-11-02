package nl

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// This is a workaround for missing SizeofNhmsg in the
	// golang.org/x/sys/unix. Once the SizeofNhmsg is added there, this
	// constant can be removed.
	sizeofNhmsg = 8
)

type Nhmsg struct {
	unix.Nhmsg
}

func (msg *Nhmsg) Len() int {
	return sizeofNhmsg
}

func DeserializeNhmsg(b []byte) *Nhmsg {
	if len(b) < sizeofNhmsg {
		return nil
	}
	return (*Nhmsg)(unsafe.Pointer(&b[0:sizeofNhmsg][0]))
}

func (msg *Nhmsg) Serialize() []byte {
	return (*(*[sizeofNhmsg]byte)(unsafe.Pointer(msg)))[:]
}
