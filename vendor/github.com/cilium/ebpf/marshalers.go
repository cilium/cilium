package ebpf

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"reflect"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf/internal"

	"github.com/pkg/errors"
)

func marshalPtr(data interface{}, length int) (syscallPtr, error) {
	if ptr, ok := data.(unsafe.Pointer); ok {
		return newPtr(ptr), nil
	}

	buf, err := marshalBytes(data, length)
	if err != nil {
		return syscallPtr{}, err
	}

	return newPtr(unsafe.Pointer(&buf[0])), nil
}

func marshalBytes(data interface{}, length int) (buf []byte, err error) {
	switch value := data.(type) {
	case encoding.BinaryMarshaler:
		buf, err = value.MarshalBinary()
	case string:
		buf = []byte(value)
	case []byte:
		buf = value
	case unsafe.Pointer:
		err = errors.New("can't marshal from unsafe.Pointer")
	default:
		var wr bytes.Buffer
		err = binary.Write(&wr, internal.NativeEndian, value)
		err = errors.Wrapf(err, "encoding %T", value)
		buf = wr.Bytes()
	}
	if err != nil {
		return nil, err
	}

	if len(buf) != length {
		return nil, errors.Errorf("%T doesn't marshal to %d bytes", data, length)
	}
	return buf, nil
}

func makeBuffer(dst interface{}, length int) (syscallPtr, []byte) {
	if ptr, ok := dst.(unsafe.Pointer); ok {
		return newPtr(ptr), nil
	}

	buf := make([]byte, length)
	return newPtr(unsafe.Pointer(&buf[0])), buf
}

func unmarshalBytes(data interface{}, buf []byte) error {
	switch value := data.(type) {
	case unsafe.Pointer:
		sh := &reflect.SliceHeader{
			Data: uintptr(value),
			Len:  len(buf),
			Cap:  len(buf),
		}

		dst := *(*[]byte)(unsafe.Pointer(sh))
		copy(dst, buf)
		runtime.KeepAlive(value)
		return nil
	case encoding.BinaryUnmarshaler:
		return value.UnmarshalBinary(buf)
	case *string:
		*value = string(buf)
		return nil
	case *[]byte:
		*value = buf
		return nil
	case string:
		return errors.New("require pointer to string")
	case []byte:
		return errors.New("require pointer to []byte")
	default:
		rd := bytes.NewReader(buf)
		err := binary.Read(rd, internal.NativeEndian, value)
		return errors.Wrapf(err, "decoding %T", value)
	}
}

// marshalPerCPUValue encodes a slice containing one value per
// possible CPU into a buffer of bytes.
//
// Values are initialized to zero if the slice has less elements than CPUs.
//
// slice must have a type like []elementType.
func marshalPerCPUValue(slice interface{}, elemLength int) (syscallPtr, error) {
	sliceType := reflect.TypeOf(slice)
	if sliceType.Kind() != reflect.Slice {
		return syscallPtr{}, errors.New("per-CPU value requires slice")
	}

	possibleCPUs, err := internal.PossibleCPUs()
	if err != nil {
		return syscallPtr{}, err
	}

	sliceValue := reflect.ValueOf(slice)
	sliceLen := sliceValue.Len()
	if sliceLen > possibleCPUs {
		return syscallPtr{}, errors.Errorf("per-CPU value exceeds number of CPUs")
	}

	alignedElemLength := align(elemLength, 8)
	buf := make([]byte, alignedElemLength*possibleCPUs)

	for i := 0; i < sliceLen; i++ {
		elem := sliceValue.Index(i).Interface()
		elemBytes, err := marshalBytes(elem, elemLength)
		if err != nil {
			return syscallPtr{}, err
		}

		offset := i * alignedElemLength
		copy(buf[offset:offset+elemLength], elemBytes)
	}

	return newPtr(unsafe.Pointer(&buf[0])), nil
}

// unmarshalPerCPUValue decodes a buffer into a slice containing one value per
// possible CPU.
//
// valueOut must have a type like *[]elementType
func unmarshalPerCPUValue(slicePtr interface{}, elemLength int, buf []byte) error {
	slicePtrType := reflect.TypeOf(slicePtr)
	if slicePtrType.Kind() != reflect.Ptr || slicePtrType.Elem().Kind() != reflect.Slice {
		return errors.Errorf("per-cpu value requires pointer to slice")
	}

	possibleCPUs, err := internal.PossibleCPUs()
	if err != nil {
		return err
	}

	sliceType := slicePtrType.Elem()
	slice := reflect.MakeSlice(sliceType, possibleCPUs, possibleCPUs)

	sliceElemType := sliceType.Elem()
	sliceElemIsPointer := sliceElemType.Kind() == reflect.Ptr
	if sliceElemIsPointer {
		sliceElemType = sliceElemType.Elem()
	}

	step := len(buf) / possibleCPUs
	if step < elemLength {
		return errors.Errorf("per-cpu element length is larger than available data")
	}
	for i := 0; i < possibleCPUs; i++ {
		var elem interface{}
		if sliceElemIsPointer {
			newElem := reflect.New(sliceElemType)
			slice.Index(i).Set(newElem)
			elem = newElem.Interface()
		} else {
			elem = slice.Index(i).Addr().Interface()
		}

		// Make a copy, since unmarshal can hold on to itemBytes
		elemBytes := make([]byte, elemLength)
		copy(elemBytes, buf[:elemLength])

		err := unmarshalBytes(elem, elemBytes)
		if err != nil {
			return errors.Wrapf(err, "cpu %d", i)
		}

		buf = buf[step:]
	}

	reflect.ValueOf(slicePtr).Elem().Set(slice)
	return nil
}

func align(n, alignment int) int {
	return (int(n) + alignment - 1) / alignment * alignment
}
