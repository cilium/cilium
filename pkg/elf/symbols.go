// Copyright 2019 Authors of Cilium
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

package elf

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"
	"unsafe"
)

const (
	dataSection = ".data"
	mapSection  = "maps"

	nullTerminator     = byte(0)
	relocSectionPrefix = ".rel"

	// nMapRelocations is an approximation of the number of offsets in an
	// ELF relating to map names that need to be adjusted. It's used for
	// map initialization within 'Symbols'.
	//
	// $ readelf -a bpf/bpf_lxc.o | grep "cilium_.*_" | grep "^0000" | wc -l
	// 51
	nMapRelocations = 64
)

type symbolKind uint32

const (
	symbolUint32 = symbolKind(1)
	symbolString = symbolKind(2)
)

func (k symbolKind) String() string {
	switch k {
	case symbolUint32:
		return "uint32"
	case symbolString:
		return "string"
	}
	return "unknown"
}

// symbol stores the location and type of a symbol within the ELF file.
type symbol struct {
	name   string
	kind   symbolKind
	offset uint64
	size   uint64
}

func newSymbol(name string, kind symbolKind, offset, size uint64) symbol {
	return symbol{
		name:   name,
		kind:   kind,
		offset: offset,
		size:   size,
	}
}

func newVariable(name string, offset uint64) symbol {
	size := uint64(unsafe.Sizeof(symbolUint32))
	return newSymbol(name, symbolUint32, offset, size)
}

func newString(name string, offset uint64) symbol {
	return newSymbol(name, symbolString, offset, uint64(len(name)))
}

type symbolSlice []symbol

// sort a slice of symbols by offset.
func (c symbolSlice) sort() symbolSlice {
	sort.Slice(c, func(i, j int) bool { return c[i].offset < c[j].offset })
	return c
}

type symbols struct {
	// data caches static 32-bit variables by name.
	data map[string]symbol
	// strings caches string symbols by name.
	strings map[string]symbol
}

func (s *symbols) sort() symbolSlice {
	result := make(symbolSlice, 0)
	for _, c := range s.data {
		result = append(result, c)
	}
	for _, c := range s.strings {
		result = append(result, c)
	}
	return result.sort()
}

func isGlobalData(sym elf.Symbol) bool {
	return (elf.ST_TYPE(sym.Info) == elf.STT_NOTYPE ||
		elf.ST_TYPE(sym.Info) == elf.STT_OBJECT) &&
		elf.ST_BIND(sym.Info) == elf.STB_GLOBAL &&
		elf.ST_VISIBILITY(sym.Other) == elf.STV_DEFAULT
}

func readStringOffset(e *elf.File, r io.ReadSeeker, symbolOffset int64) (uint64, error) {
	if _, err := r.Seek(symbolOffset, io.SeekStart); err != nil {
		return 0, err
	}

	switch e.Class {
	case elf.ELFCLASS32:
		var sym32 elf.Sym32
		if err := binary.Read(r, e.ByteOrder, &sym32); err != nil {
			return 0, err
		}
		return uint64(sym32.Name), nil
	case elf.ELFCLASS64:
		var sym64 elf.Sym64
		if err := binary.Read(r, e.ByteOrder, &sym64); err != nil {
			return 0, err
		}
		return uint64(sym64.Name), nil
	}
	return 0, fmt.Errorf("unsupported ELF type %d", e.Class)
}

// extractFrom processes the specified ELF and populates the received symbols
// object with data and string offsets in the file, for later substitution.
func (s *symbols) extractFrom(e *elf.File) error {
	dataOffsets := make(map[string]symbol)
	stringOffsets := make(map[string]symbol, nMapRelocations)

	symbols, err := e.Symbols()
	if err != nil {
		return err
	}
	symtab := e.SectionByType(elf.SHT_SYMTAB)
	strtab := e.Sections[symtab.Link]

	// Scan symbol table for offsets of static data and symbol names.
	symbolReader := symtab.Open()
	for i, sym := range symbols {
		// BTF extensions like line info not recognized by normal ELF parsers
		if elf.ST_TYPE(sym.Info) == elf.STT_FILE {
			continue
		}
		section := e.Sections[sym.Section]
		switch {
		case section.Flags&elf.SHF_COMPRESSED > 0:
			return fmt.Errorf("compressed %s section not supported", section.Name)
		case !isGlobalData(sym):
			// LBB is a common llvm symbol prefix (basic block);
			// Don't flood the logs with messages about it.
			if !strings.HasPrefix(sym.Name, "LBB") {
				log.Debugf("Skipping %s", sym.Name)
			}
			continue
		case section.Name == dataSection:
			// Offset from start of binary to variable inside .data
			offset := section.Offset + sym.Value
			dataOffsets[sym.Name] = newVariable(sym.Name, offset)
			log.WithField(fieldSymbol, sym.Name).Debugf("Found variable with offset %d", offset)
		case section.Name == mapSection:
			// From the Golang Documentation:
			//   "For compatibility with Go 1.0, Symbols omits the
			//   the null symbol at index 0."
			// We must reverse this when reading directly.
			symbolOffset := int64(i+1) * int64(symtab.Entsize)
			symOffsetInStrtab, err := readStringOffset(e, symbolReader, symbolOffset)
			if err != nil {
				return err
			}
			// Offset from start of binary to name inside .strtab
			symOffset := strtab.Offset + symOffsetInStrtab
			stringOffsets[sym.Name] = newString(sym.Name, symOffset)
			log.WithField(fieldSymbol, sym.Name).Debugf("Found symbol with offset %d", symOffset)
		default:
			log.WithField(fieldSymbol, sym.Name).Debugf("Found symbol with unknown section reference %d", sym.Section)
		}
	}

	// Scan string table for offsets of section names.
	stringReader := bufio.NewReader(strtab.Open())
	var elfString string
	for off := uint64(0); off < strtab.Size; off += uint64(len(elfString)) {
		// off is the offset within the string table.
		elfString, err = stringReader.ReadString(nullTerminator)
		if err != nil && err != io.EOF {
			return err
		}

		// We only need to worry about sections with relocations.
		if !strings.HasPrefix(elfString, relocSectionPrefix) {
			if err == io.EOF {
				break
			}
			continue
		}

		elfEnd := len(elfString)
		if elfString[elfEnd-1] == nullTerminator {
			elfEnd--
		}
		relocOffset := uint64(len(relocSectionPrefix))
		secName := elfString[relocOffset:elfEnd]
		if sec := e.Section(secName); sec != nil {
			// Offset from start of binary to name inside .strtab
			globalOffset := strtab.Offset + off + relocOffset
			stringOffsets[secName] = newString(secName, globalOffset)
			log.WithField(fieldSymbol, secName).Debugf("Found section with offset %d", globalOffset)
		}

		if err == io.EOF {
			break
		}
	}

	s.data = dataOffsets
	s.strings = stringOffsets
	return nil
}
