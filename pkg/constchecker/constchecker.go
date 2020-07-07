// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package constchecker

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"reflect"

	"gopkg.in/check.v1"
)

// ErrElf marks an ELF-related error
type ErrElf struct {
	msg string
}

func (e *ErrElf) Error() string {
	return fmt.Sprintf("elf error: %s", e.msg)
}

// ErrSizeMismatch marks a size mismatch
type ErrSizeMismatch struct {
	Name             string
	SizeBpf, SizeVal uint64
}

func (e *ErrSizeMismatch) Error() string {
	return fmt.Sprintf("size mismatch for symbol %s: bpf size:%d val size:%d", e.Name, e.SizeBpf, e.SizeVal)
}

// ErrSym marks a generic error for a given symbol
type ErrSym struct {
	Name string
	msg  string
}

func (e *ErrSym) Error() string {
	return fmt.Sprintf("error for symbol %s: %s", e.Name, e.msg)
}

// ErrValueMismatch marks a value mismatch
type ErrValueMismatch struct {
	Name        string
	ValBpf, Val reflect.Value
}

func (e *ErrValueMismatch) Error() string {
	return fmt.Sprintf("value mismatch for symbol %s: bpf:%v val:%v", e.Name, e.ValBpf, e.Val)
}

// Check reads symbols from the .rodata section and compares their values
// against given toCheck values.
// It returns  the first error it encounters, or nil if succesful.
func Check(pathToObj string, toCheck map[string]reflect.Value) error {
	f, err := elf.Open(pathToObj)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", pathToObj, err)
	}
	defer f.Close()

	elfSyms, err := f.Symbols()
	if err != nil {
		return &ErrElf{"no symbols"}
	}

	elfSymsMap := make(map[string]elf.Symbol, len(elfSyms))
	for _, sym := range elfSyms {
		elfSymsMap[sym.Name] = sym
	}

	rodata := f.Section(".rodata")
	if rodata == nil {
		return &ErrElf{"missing .rodata"}
	}
	rodataRd := rodata.Open()

	for name, val := range toCheck {
		elfSym, ok := elfSymsMap[name]
		if !ok {
			return &ErrSym{
				Name: name,
				msg:  "does not exist",
			}
		}

		size := uint64(val.Type().Size())
		if size != elfSym.Size {
			return &ErrSizeMismatch{
				Name:    name,
				SizeBpf: elfSym.Size,
				SizeVal: size,
			}
		}

		// NB: we use this function for  constants, so we expect to
		// find them in .rodata
		sect := f.Sections[elfSym.Section]
		if sect.SectionHeader.Name != ".rodata" {
			return &ErrSym{
				Name: name,
				msg:  "not in .rodata",
			}
		}

		errReadFailed := ErrSym{
			Name: name,
			msg:  "read failed",
		}

		_, err := rodataRd.Seek(int64(elfSym.Value), io.SeekStart)
		if err != nil {
			return &errReadFailed
		}

		switch val.Kind() {

		// Some scaffolding in case we want to add more types:
		// case reflect.Int8:
		// case reflect.Int16:
		// case reflect.Int32:
		// case reflect.Int64:

		case reflect.Uint8:
			var v uint8
			err := binary.Read(rodataRd, f.FileHeader.ByteOrder, &v)
			if err != nil {
				return &errReadFailed
			}
			if v != uint8(val.Uint()) {
				return &ErrValueMismatch{
					Name:   name,
					ValBpf: reflect.ValueOf(v),
					Val:    val,
				}
			}

		// Some scaffolding in case we want to add more types:
		// case reflect.Uint16:
		// case reflect.Uint32:

		case reflect.Uint64:
			var v uint64
			err := binary.Read(rodataRd, f.FileHeader.ByteOrder, &v)
			if err != nil {
				return &errReadFailed
			}
			if v != val.Uint() {
				return &ErrValueMismatch{
					Name:   name,
					ValBpf: reflect.ValueOf(v),
					Val:    val,
				}
			}

		default:
			return &ErrSym{
				Name: name,
				msg:  fmt.Sprintf("cannot handle kind %s", val.Kind()),
			}
		}
	}

	return nil
}

// check using BPF file pointed by environment var CILIUM_CONSTCHECKER_BPF_OBJ (or skip)
func CheckEnvErr(c *check.C, toCheck map[string]reflect.Value) error {
	path := os.Getenv("CILIUM_CONSTCHECKER_BPF_OBJ")
	if len(path) == 0 {
		c.Skip("skipping constcheck (CILIUM_CONSTCHECKER_BPF_OBJ variable not set)")
	}
	return Check(path, toCheck)
}

// check using BPF file pointed by environment var CILIUM_CONSTCHECKER_BPF_OBJ (or skip)
func CheckEnv(c *check.C, toCheck map[string]reflect.Value) {
	err := CheckEnvErr(c, toCheck)
	c.Assert(err, check.IsNil)
}
