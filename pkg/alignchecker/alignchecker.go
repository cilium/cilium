// Copyright 2018-2019 Authors of Cilium
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

package alignchecker

import (
	"bytes"
	"compress/zlib"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// CheckStructAlignments checks whether size and offsets match of the given
// C and Go structs which are listed in the given toCheck map (C struct name =>
// Go struct reflect.Type).
//
// C struct size info is extracted from the given ELF object file debug section
// encoded in DWARF.
//
// To find a matching C struct field, a Go field has to be tagged with
// `align:"field_name_in_c_struct". In the case of unnamed union field, such
// union fields can be referred with special tags - `align:"$union0"`,
// `align:"$union1"`, etc.
func CheckStructAlignments(pathToObj string, toCheck map[string]reflect.Type) error {
	f, err := elf.Open(pathToObj)
	if err != nil {
		return fmt.Errorf("elf failed to open %s: %s", pathToObj, err)
	}
	defer f.Close()

	d, err := getDWARFFromELF(f)
	if err != nil {
		return fmt.Errorf("cannot parse DWARF debug info %s: %s", pathToObj, err)
	}

	structs, err := getStructInfosFromDWARF(d, toCheck)
	if err != nil {
		return fmt.Errorf("cannot extract struct infos from DWARF %s: %s", pathToObj, err)
	}

	return check(toCheck, structs)
}

// structInfo contains C struct info
type structInfo struct {
	size         int64
	fieldOffsets map[string]int64
}

func getStructInfosFromDWARF(d *dwarf.Data, toCheck map[string]reflect.Type) (map[string]structInfo, error) {
	structs := make(map[string]structInfo)

	r := d.Reader()

	for entry, err := r.Next(); entry != nil && err == nil; entry, err = r.Next() {
		// Read only DWARF struct entries
		if entry.Tag != dwarf.TagStructType {
			continue
		}

		t, err := d.Type(entry.Offset)
		if err != nil {
			return nil, fmt.Errorf("cannot read DWARF info section at offset %d: %s",
				entry.Offset, err)
		}

		st := t.(*dwarf.StructType)

		if _, found := toCheck[st.StructName]; found {
			unionCount := 0
			offsets := make(map[string]int64)
			for _, field := range st.Field {
				n := field.Name
				// Create surrogate names ($union0, $union1, etc) for unnamed
				// union members
				if n == "" {
					if t, ok := field.Type.(*dwarf.StructType); ok {
						if t.Kind == "union" {
							n = fmt.Sprintf("$union%d", unionCount)
							unionCount++
						}
					}
				}
				offsets[n] = field.ByteOffset
			}
			structs[st.StructName] = structInfo{
				size:         st.ByteSize,
				fieldOffsets: offsets,
			}
		}
	}

	return structs, nil
}

func check(toCheck map[string]reflect.Type, structs map[string]structInfo) error {
	for name, g := range toCheck {
		c, found := structs[name]
		if !found {
			return fmt.Errorf("C struct %s not found", name)
		}

		if c.size != int64(g.Size()) {
			return fmt.Errorf("struct sizes do not match: %s (%d) vs %s (%d)",
				g, g.Size(), name, c.size)
		}

		for i := 0; i < g.NumField(); i++ {
			fieldName := g.Field(i).Tag.Get("align")
			// Ignore fields without `align` struct tag
			if fieldName == "" {
				continue
			}
			goOffset := int64(g.Field(i).Offset)
			cOffset := structs[name].fieldOffsets[fieldName]
			if goOffset != cOffset {
				return fmt.Errorf("%s.%s offset (%d) does not match with %s.%s (%d)",
					g, g.Field(i).Name, goOffset, name, fieldName, cOffset)
			}
		}
	}

	return nil
}

// Adopted from elf.File.DWARF
// https://github.com/golang/go/blob/master/src/debug/elf/file.go (go1.11.2).
//
// The former method function tries to apply relocations when extracting DWARF
// debug sections. Unfortunately, the relocations are not implemented for EM_BPF,
// so the method fails.
//
// For struct alignment checks, no relocations are needed, so we comment out
// the relocation bits.
//
// NOTE: DO NOT USE THE FUNCTION FOR ANYTHING ELSE!
func getDWARFFromELF(f *elf.File) (*dwarf.Data, error) {
	dwarfSuffix := func(s *elf.Section) string {
		switch {
		case strings.HasPrefix(s.Name, ".debug_"):
			return s.Name[7:]
		case strings.HasPrefix(s.Name, ".zdebug_"):
			return s.Name[8:]
		default:
			return ""
		}

	}
	// sectionData gets the data for s, checks its size, and
	// applies any applicable relations.
	sectionData := func(i int, s *elf.Section) ([]byte, error) {
		b, err := s.Data()
		if err != nil && uint64(len(b)) < s.Size {
			return nil, err
		}

		if len(b) >= 12 && string(b[:4]) == "ZLIB" {
			dlen := binary.BigEndian.Uint64(b[4:12])
			dbuf := make([]byte, dlen)
			r, err := zlib.NewReader(bytes.NewBuffer(b[12:]))
			if err != nil {
				return nil, err
			}
			if _, err := io.ReadFull(r, dbuf); err != nil {
				return nil, err
			}
			if err := r.Close(); err != nil {
				return nil, err
			}
			b = dbuf
		}

		for _, r := range f.Sections {
			if r.Type != elf.SHT_RELA && r.Type != elf.SHT_REL {
				continue
			}
			if int(r.Info) != i {
				continue
			}
			//rd, err := r.Data()
			_, err := r.Data()
			if err != nil {
				return nil, err
			}
			// err = f.applyRelocations(b, rd)
			// if err != nil {
			// 	return nil, err
			// }
		}
		return b, nil
	}

	// There are many other DWARF sections, but these
	// are the ones the debug/dwarf package uses.
	// Don't bother loading others.
	var dat = map[string][]byte{"abbrev": nil, "info": nil, "str": nil, "line": nil, "ranges": nil}
	for i, s := range f.Sections {
		suffix := dwarfSuffix(s)
		if suffix == "" {
			continue
		}
		if _, ok := dat[suffix]; !ok {
			continue
		}
		b, err := sectionData(i, s)
		if err != nil {
			return nil, err
		}
		dat[suffix] = b
	}

	d, err := dwarf.New(dat["abbrev"], nil, nil, dat["info"], dat["line"], nil, dat["ranges"], dat["str"])
	if err != nil {
		return nil, err
	}

	// Look for DWARF4 .debug_types sections.
	for i, s := range f.Sections {
		suffix := dwarfSuffix(s)
		if suffix != "types" {
			continue
		}

		b, err := sectionData(i, s)
		if err != nil {
			return nil, err
		}

		err = d.AddTypes(fmt.Sprintf("types-%d", i), b)
		if err != nil {
			return nil, err
		}
	}

	return d, nil
}
