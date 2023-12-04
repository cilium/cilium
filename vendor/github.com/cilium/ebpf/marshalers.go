package ebpf

import (
	"encoding"
	"errors"
	"fmt"
	"reflect"
	"unsafe"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/sysenc"
)

// marshalMapSyscallInput converts an arbitrary value into a pointer suitable
// to be passed to the kernel.
//
// As an optimization, it returns the original value if it is an
// unsafe.Pointer.
func marshalMapSyscallInput(data any, length int) (sys.Pointer, error) {
	if ptr, ok := data.(unsafe.Pointer); ok {
		return sys.NewPointer(ptr), nil
	}

	buf, err := sysenc.Marshal(data, length)
	if err != nil {
		return sys.Pointer{}, err
	}

	return buf.Pointer(), nil
}

func makeMapSyscallOutput(dst any, length int) sysenc.Buffer {
	if ptr, ok := dst.(unsafe.Pointer); ok {
		return sysenc.UnsafeBuffer(ptr)
	}

	_, ok := dst.(encoding.BinaryUnmarshaler)
	if ok {
		return sysenc.SyscallOutput(nil, length)
	}

	return sysenc.SyscallOutput(dst, length)
}

// marshalPerCPUValue encodes a slice containing one value per
// possible CPU into a buffer of bytes.
//
// Values are initialized to zero if the slice has less elements than CPUs.
func marshalPerCPUValue(slice any, elemLength int) (sys.Pointer, error) {
	sliceType := reflect.TypeOf(slice)
	if sliceType.Kind() != reflect.Slice {
		return sys.Pointer{}, errors.New("per-CPU value requires slice")
	}

	possibleCPUs, err := PossibleCPU()
	if err != nil {
		return sys.Pointer{}, err
	}

	sliceValue := reflect.ValueOf(slice)
	sliceLen := sliceValue.Len()
	if sliceLen > possibleCPUs {
		return sys.Pointer{}, fmt.Errorf("per-CPU value exceeds number of CPUs")
	}

	alignedElemLength := internal.Align(elemLength, 8)
	buf := make([]byte, alignedElemLength*possibleCPUs)

	for i := 0; i < sliceLen; i++ {
		elem := sliceValue.Index(i).Interface()
		elemBytes, err := sysenc.Marshal(elem, elemLength)
		if err != nil {
			return sys.Pointer{}, err
		}

		offset := i * alignedElemLength
		elemBytes.CopyTo(buf[offset : offset+elemLength])
	}

	return sys.NewSlicePointer(buf), nil
}

// unmarshalPerCPUValue decodes a buffer into a slice containing one value per
// possible CPU.
//
// slice must be a literal slice and not a pointer.
func unmarshalPerCPUValue(slice any, elemLength int, buf []byte) error {
	sliceType := reflect.TypeOf(slice)
	if sliceType.Kind() != reflect.Slice {
		return fmt.Errorf("per-CPU value requires a slice")
	}

	possibleCPUs, err := PossibleCPU()
	if err != nil {
		return err
	}

	sliceValue := reflect.ValueOf(slice)
	if sliceValue.Len() != possibleCPUs {
		return fmt.Errorf("per-CPU slice has incorrect length, expected %d, got %d",
			possibleCPUs, sliceValue.Len())
	}

	sliceElemType := sliceType.Elem()
	sliceElemIsPointer := sliceElemType.Kind() == reflect.Ptr
	stride := internal.Align(elemLength, 8)
	for i := 0; i < possibleCPUs; i++ {
		var elem any
		v := sliceValue.Index(i)
		if sliceElemIsPointer {
			if !v.Elem().CanAddr() {
				return fmt.Errorf("per-CPU slice elements cannot be nil")
			}
			elem = v.Elem().Addr().Interface()
		} else {
			elem = v.Addr().Interface()
		}
		err := sysenc.Unmarshal(elem, buf[:elemLength])
		if err != nil {
			return fmt.Errorf("cpu %d: %w", i, err)
		}

		buf = buf[stride:]
	}

	return nil
}
