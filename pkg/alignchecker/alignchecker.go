// Copyright 2018-2020 Authors of Cilium
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
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"reflect"
)

// CheckStructAlignments checks whether size and offsets match of the given
// C and Go structs which are listed in the given toCheck map (C struct name =>
// Go struct []reflect.Type).
//
// C struct size info is extracted from the given ELF object file debug section
// encoded in DWARF.
//
// To find a matching C struct field, a Go field has to be tagged with
// `align:"field_name_in_c_struct". In the case of unnamed union field, such
// union fields can be referred with special tags - `align:"$union0"`,
// `align:"$union1"`, etc.
func CheckStructAlignments(pathToObj string, toCheck map[string][]reflect.Type, checkOffsets bool) error {
	f, err := elf.Open(pathToObj)
	if err != nil {
		return fmt.Errorf("elf failed to open %s: %s", pathToObj, err)
	}
	defer f.Close()

	d, err := getDWARFFromELF(f)
	if err != nil {
		return fmt.Errorf("cannot parse DWARF debug info %s: %s", pathToObj, err)
	}

	structInfo, err := getStructInfosFromDWARF(d, toCheck)
	if err != nil {
		return fmt.Errorf("cannot extract struct info from DWARF %s: %s", pathToObj, err)
	}

	for cName, goStructs := range toCheck {
		if err := check(cName, goStructs, structInfo, checkOffsets); err != nil {
			return err
		}
	}
	return nil
}

// structInfo contains C struct info
type structInfo struct {
	size         int64
	fieldOffsets map[string]int64
}

func getStructInfosFromDWARF(d *dwarf.Data, toCheck map[string][]reflect.Type) (map[string]structInfo, error) {
	structs := make(map[string]structInfo)

	r := d.Reader()

	for entry, err := r.Next(); entry != nil && err == nil; entry, err = r.Next() {
		t, err := d.Type(entry.Offset)
		if err != nil {
			continue
		}

		if st, ok := t.(*dwarf.StructType); ok {
			if _, found := toCheck[st.StructName]; found {
				unionCount := 0
				offsets := make(map[string]int64, len(st.Field))
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
		} else if t.Common() != nil {
			if _, found := toCheck[t.Common().Name]; found {
				structs[t.Common().Name] = structInfo{
					size:         t.Common().ByteSize,
					fieldOffsets: nil,
				}
			}
		}
	}

	return structs, nil
}

func check(name string, toCheck []reflect.Type, structs map[string]structInfo, checkOffsets bool) error {
	for _, g := range toCheck {
		c, found := structs[name]
		if !found {
			return fmt.Errorf("could not find C struct %s", name)
		}

		if c.size != int64(g.Size()) {
			return fmt.Errorf("%s(%d) size does not match %s(%d)", g, g.Size(),
				name, c.size)
		}

		if !checkOffsets {
			continue
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
				return fmt.Errorf("%s.%s offset(%d) does not match %s.%s(%d)",
					g, g.Field(i).Name, goOffset, name, fieldName, cOffset)
			}
		}
	}

	return nil
}
