package ebpf

import (
	"github.com/pkg/errors"
)

// MapABI describes a Map.
//
// Use it to assert that a Map matches what your code expects.
type MapABI struct {
	Type       MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	InnerMap   *MapABI
}

func newMapABIFromSpec(spec *MapSpec) *MapABI {
	var inner *MapABI
	if spec.InnerMap != nil {
		inner = newMapABIFromSpec(spec.InnerMap)
	}

	return &MapABI{
		spec.Type,
		spec.KeySize,
		spec.ValueSize,
		spec.MaxEntries,
		inner,
	}
}

func newMapABIFromFd(fd *bpfFD) (*MapABI, error) {
	info, err := bpfGetMapInfoByFD(fd)
	if err != nil {
		return nil, err
	}

	mapType := MapType(info.mapType)
	if mapType == ArrayOfMaps || mapType == HashOfMaps {
		return nil, errors.New("can't get map info for nested maps")
	}

	return &MapABI{
		mapType,
		info.keySize,
		info.valueSize,
		info.maxEntries,
		nil,
	}, nil
}

// Check verifies that a Map conforms to the ABI.
//
// Members of ABI which have the zero value of their type are not checked.
func (abi *MapABI) Check(m *Map) error {
	return abi.check(&m.abi)
}

func (abi *MapABI) check(other *MapABI) error {
	if abi.Type != UnspecifiedMap && other.Type != abi.Type {
		return errors.Errorf("expected map type %s, have %s", abi.Type, other.Type)
	}
	if err := checkUint32("key size", abi.KeySize, other.KeySize); err != nil {
		return err
	}
	if err := checkUint32("value size", abi.ValueSize, other.ValueSize); err != nil {
		return err
	}
	if err := checkUint32("max entries", abi.MaxEntries, other.MaxEntries); err != nil {
		return err
	}

	if abi.InnerMap == nil {
		if abi.Type == ArrayOfMaps || abi.Type == HashOfMaps {
			return errors.New("missing inner map ABI")
		}

		return nil
	}

	if other.InnerMap == nil {
		return errors.New("missing inner map")
	}

	return errors.Wrap(abi.InnerMap.check(other.InnerMap), "inner map")
}

// ProgramABI describes a Program.
//
// Use it to assert that a Program matches what your code expects.
type ProgramABI struct {
	Type ProgramType
}

func newProgramABIFromSpec(spec *ProgramSpec) *ProgramABI {
	return &ProgramABI{
		spec.Type,
	}
}

func newProgramABIFromFd(fd *bpfFD) (*ProgramABI, error) {
	info, err := bpfGetProgInfoByFD(fd)
	if err != nil {
		return nil, err
	}

	return &ProgramABI{
		Type: ProgramType(info.progType),
	}, nil
}

// Check verifies that a Program conforms to the ABI.
//
// Members which have the zero value of their type
// are not checked.
func (abi *ProgramABI) Check(prog *Program) error {
	if abi.Type != UnspecifiedProgram && prog.abi.Type != abi.Type {
		return errors.Errorf("expected program type %s, have %s", abi.Type, prog.abi.Type)
	}

	return nil
}

func checkUint32(name string, want, have uint32) error {
	if want != 0 && have != want {
		return errors.Errorf("expected %s to be %d, have %d", name, want, have)
	}
	return nil
}
