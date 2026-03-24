// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"flag"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/davecgh/go-spew/spew"

	"github.com/cilium/cilium/tools/stackwhere/dwarf/leb128"
	"github.com/cilium/cilium/tools/stackwhere/dwarf/op"
)

var flagCallStack = flag.Bool("call-stack", false, "Show the full callstack of a variable")

func main() {
	flag.Parse()

	if len(flag.Args()) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: ./stackwhere <binary> [function]\n")
		os.Exit(1)
	}

	obj, err := elf.Open(flag.Args()[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	dbg, err := DWARF(obj)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	llt, err := newLoclistTable(obj)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	tree := newTree(llt)
	var cur *node

	r := dbg.Reader()
	for entry, err := r.Next(); entry != nil; entry, err = r.Next() {
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}

		if entry.Tag == 0 {
			cur = cur.parent
			continue
		}

		n := newNode(tree, entry)
		if cur == nil {
			if entry.Tag != dwarf.TagCompileUnit {
				fmt.Fprintf(os.Stderr, "unexpected root entry with tag %s\n", entry.Tag)
				os.Exit(1)
			}

			tree.root = n
			cur = n

			lr, err := dbg.LineReader(entry)
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}

			tree.files = lr.Files()
		} else {
			cur.children = append(cur.children, n)
			n.parent = cur

			if entry.Children {
				cur = n
			}
		}

		tree.AddToIndex(n)
	}

	if len(flag.Args()) >= 2 {
		showStackSlots(tree, flag.Args()[1])
	} else {
		showProgramStackUsage(tree)
	}
}

func showStackSlots(tree *tree, functionName string) {
	for _, n := range tree.byType[dwarf.TagSubprogram] {
		name := n.entry.Val(dwarf.AttrName)
		if name == nil {
			continue
		}
		if name.(string) != functionName {
			continue
		}

		entrypoint := n
		stackMap := map[int64][]*node{}
		visitPrefixOrder(n, func(n *node) {
			// We are interested in variables and function parameters since those are the things that can be stored on
			// the stack.
			if n.entry.Tag != dwarf.TagVariable && n.entry.Tag != dwarf.TagFormalParameter {
				return
			}

			// If the current variable lives on the stack, add it to the map of stack offsets to variables that live at that offset.
			offsets := stackOffsets(n)
			if len(offsets) > 0 {
				for _, offset := range offsets {
					if !slices.Contains(stackMap[offset], n) {
						stackMap[offset] = append(stackMap[offset], n)
					}
				}
			}
		})

		// Print the variables grouped by their stack offset, sorted by largest byte size first and then name.
		for _, offset := range slices.Sorted(maps.Keys(stackMap)) {
			fmt.Printf("Stack offset %d:\n", offset)
			nodes := stackMap[offset]
			slices.SortFunc(nodes, func(a, b *node) int {
				sz := int(b.ByteSize()) - int(a.ByteSize())
				if sz != 0 {
					return sz
				}

				return strings.Compare(a.Name(), b.Name())
			})

			// Remove duplicates that can occur, for example when a function is inlined multiple times and it
			// ends up reusing the same stack space.
			nodes = slices.CompactFunc(nodes, func(a, b *node) bool {
				return a.Name() == b.Name() && a.ByteSize() == b.ByteSize() && a.FileCol() == b.FileCol()
			})
			for _, n := range nodes {
				fmt.Printf("  %d - %s @ %s\n", n.ByteSize(), n.Name(), n.FileCol())

				// If the flag is set, print the full call stack that leads to the variable being stored at this stack offset.
				if *flagCallStack {
					parents := []*node{}
					p := n
					for p != nil {
						p = p.parent
						parents = append(parents, p)
						if p == entrypoint {
							break
						}
					}
					for _, parent := range parents {
						if parent.Name() == "" {
							continue
						}
						fmt.Printf("    %s @ %s\n", parent.Name(), parent.FileCol())
					}
				}
			}
		}
	}
}

func showProgramStackUsage(tree *tree) {
	stackUsagePerProgram := map[string]int64{}
	for _, prog := range tree.byType[dwarf.TagSubprogram] {
		if !isBPFProgram(prog) {
			continue
		}

		largestOffset := int64(0)
		lastSize := int64(0)
		visitPrefixOrder(prog, func(n *node) {
			// Only consider variables and function parameters since those are the things that can be stored on the stack.
			if n.entry.Tag != dwarf.TagVariable && n.entry.Tag != dwarf.TagFormalParameter {
				return
			}

			// Find all stack offsets used by this variable.
			offsets := stackOffsets(n)
			if len(offsets) == 0 {
				return
			}

			// If this was the largest stack offset we've seen so far, then the total stack usage must be at least
			// large enough to fit this variable. If this variable has the same largest offset as a previous variable,
			// but is larger than that previous variable, then the total stack usage must be increased to fit this variable.
			sz := n.ByteSize()
			for _, offset := range offsets {
				if offset > largestOffset {
					largestOffset = offset
					lastSize = sz
				}
				if offset == largestOffset && sz > lastSize {
					lastSize = sz
				}
			}
		})

		// Stack usage is always a multiple of 8 bytes, so round up to the nearest multiple of 8.
		stackUsage := largestOffset + lastSize
		if stackUsage%8 != 0 {
			stackUsage = ((stackUsage / 8) + 1) * 8
		}
		stackUsagePerProgram[prog.Name()] = stackUsage
	}

	// Sort by stack usage, largest first, and then by name, and print.
	keys := slices.Collect(maps.Keys(stackUsagePerProgram))
	slices.SortFunc(keys, func(a, b string) int {
		return int(stackUsagePerProgram[b] - stackUsagePerProgram[a])
	})
	for _, prog := range keys {
		fmt.Printf("%3d bytes - %s\n", stackUsagePerProgram[prog], prog)
	}
}

func stackOffsets(n *node) []int64 {
	offsets := []int64{}

	// DWARF can express variable locations in two ways: as a single location expression or
	// as a list of location expressions that are valid for different ranges of instructions.
	if location, err := n.Location(); err == nil && location != nil {
		// Loop over all instructions, see if any of them reference the frame base register, and thus some
		// offset into the stack.
		for _, locOp := range location {
			if locOp.Opcode == op.DW_OP_fbreg {
				if !slices.Contains(offsets, locOp.Args[0].(int64)) {
					offsets = append(offsets, locOp.Args[0].(int64))
				}
			}
		}
	} else if locList, err := n.LocationList(); err == nil && locList != nil {
		// Loop over all entries in the locations list, each entry is valid for a specific range of instructions
		// so a single variable may live in different places (registers, stack, etc) at different points in
		// the program.
		for _, entry := range locList.entries {
			// The base address + offset pair entries seem to be the only ones used in BPF object files.
			switch e := entry.(type) {
			case lleOffsetPair:
				// Loop over all instructions, see if any of them reference the frame base register, and thus some
				// offset into the stack.
				for _, locOp := range e.ops {
					if locOp.Opcode == op.DW_OP_fbreg || locOp.Opcode == op.DW_OP_breg10 {
						if !slices.Contains(offsets, locOp.Args[0].(int64)) {
							offsets = append(offsets, locOp.Args[0].(int64))
						}
					}
				}
			}
		}
	}

	slices.Sort(offsets)
	return slices.Compact(offsets)
}

func isBPFProgram(n *node) bool {
	if n.entry.Tag != dwarf.TagSubprogram {
		return false
	}

	if n.entry.Val(dwarf.AttrName) == nil {
		return false
	}

	if n.entry.Val(dwarf.AttrInline) != nil {
		return false
	}

	if n.entry.Val(dwarf.AttrType) == nil {
		return false
	}

	return true
}

const DW_TAG_LLVM_annotation = dwarf.Tag(24576)

type tree struct {
	root   *node
	index  map[dwarf.Offset]*node
	byType map[dwarf.Tag][]*node

	files []*dwarf.LineFile
	llt   *loclistTable
}

func newTree(llt *loclistTable) *tree {
	return &tree{
		index:  make(map[dwarf.Offset]*node),
		byType: make(map[dwarf.Tag][]*node),
		files:  nil,
		llt:    llt,
	}
}

func (t *tree) AddToIndex(n *node) {
	t.index[n.entry.Offset] = n
	if _, ok := t.byType[n.entry.Tag]; !ok {
		t.byType[n.entry.Tag] = []*node{}
	}
	t.byType[n.entry.Tag] = append(t.byType[n.entry.Tag], n)
}

func (t *tree) Dump() {
	t.root.Dump(0)
}

func newNode(tree *tree, entry *dwarf.Entry) *node {
	return &node{tree: tree, entry: entry}
}

type node struct {
	tree     *tree
	entry    *dwarf.Entry
	parent   *node
	children []*node
}

func (n *node) Dump(indent int) {
	fmt.Printf("%s%#x: %s\n", strings.Repeat(" ", indent), n.entry.Offset, n.entry.Tag)
	for _, attr := range n.entry.Field {
		if attr.Attr == dwarf.AttrLocation {
			if attr.Class == dwarf.ClassExprLoc {
				ops, err := n.Location()
				if err != nil {
					fmt.Printf("%s %s: <invalid location expression: %v>\n", strings.Repeat(" ", indent), attr.Attr, err)
				} else {
					fmt.Printf("%s %s:\n", strings.Repeat(" ", indent), attr.Attr)
					for _, op := range ops {
						fmt.Printf("%s    %s\n", strings.Repeat(" ", indent), op)
					}
				}
			} else if attr.Class == dwarf.ClassLocList {
				loclist, err := n.LocationList()
				if err != nil {
					fmt.Printf("%s %s: <invalid location list: %v>\n", strings.Repeat(" ", indent), attr.Attr, err)
				}
				fmt.Printf("%s %s:\n", strings.Repeat(" ", indent), attr.Attr)
				if loclist == nil {
					fmt.Printf("%s    <no location list>\n", strings.Repeat(" ", indent))
				} else {
					for _, entry := range loclist.entries {
						switch e := entry.(type) {
						case lleBaseAddressX:
							fmt.Printf("%s    DW_LLE_base_addressx: debug_addr index %d\n", strings.Repeat(" ", indent), e.debugAddrIndex)
						case lleOffsetPair:
							fmt.Printf("%s    DW_LLE_offset_pair: offset1 %#x, offset2 %#x, ops:\n", strings.Repeat(" ", indent), e.offset1, e.offset2)
							for _, op := range e.ops {
								fmt.Printf("%s         %s\n", strings.Repeat(" ", indent), op)
							}
						case lleStartLength:
							fmt.Printf("%s    DW_LLE_start_length: start %#x, length %#x\n", strings.Repeat(" ", indent), e.start, e.length)
						default:
							fmt.Printf("%s    unknown entry type %T\n", strings.Repeat(" ", indent), e)
						}
					}
				}
			}
			continue
		}

		if attr.Attr == dwarf.AttrType {
			typeEntry := n.Type()
			if typeEntry == nil {
				fmt.Printf("%s %s: <invalid type reference>\n", strings.Repeat(" ", indent), attr.Attr)
			} else {
				fmt.Printf("%s %s: %s\n", strings.Repeat(" ", indent), attr.Attr, typeEntry.Name())
				typeEntry.Dump(indent + 1)
			}
			continue
		}

		if attr.Attr == dwarf.AttrDeclFile {
			fmt.Printf("%s %s: %s\n", strings.Repeat(" ", indent), attr.Attr, n.tree.files[attr.Val.(int64)].Name)
			continue
		}

		fmt.Printf("%s %s: %#v\n", strings.Repeat(" ", indent), attr.Attr, spew.NewFormatter(attr.Val))
		if attr.Attr == dwarf.AttrAbstractOrigin {
			originEntry, ok := n.tree.index[attr.Val.(dwarf.Offset)]
			if ok {
				originEntry.Dump(indent + 1)
			}
		}
	}
	for _, c := range n.children {
		c.Dump(indent + 1)
	}
}

func (n *node) AbstractOrigin() *node {
	abstractOrigin := n.entry.Val(dwarf.AttrAbstractOrigin)
	if abstractOrigin == nil {
		return nil
	}

	originEntry, ok := n.tree.index[abstractOrigin.(dwarf.Offset)]
	if !ok {
		return nil
	}

	return originEntry
}

func (n *node) Name() string {
	name := n.entry.Val(dwarf.AttrName)
	if name != nil {
		return name.(string)
	}

	abstractOrigin := n.AbstractOrigin()
	if abstractOrigin != nil {
		return abstractOrigin.Name()
	}

	return ""
}

func (n *node) rawLocation() []byte {
	location := n.entry.Val(dwarf.AttrLocation)
	if location != nil {
		if locationBytes, ok := location.([]byte); ok {
			return locationBytes
		}

		return nil
	}

	abstractOrigin := n.AbstractOrigin()
	if abstractOrigin != nil {
		return abstractOrigin.rawLocation()
	}

	return nil
}

func (n *node) ByteSize() int64 {
	if n.entry.Tag == dwarf.TagPointerType {
		// Assume 64-bit pointers if byte size is not specified.
		return 8
	}

	byteSize := n.entry.Val(dwarf.AttrByteSize)
	if byteSize != nil {
		return byteSize.(int64)
	}

	abstractOrigin := n.AbstractOrigin()
	if abstractOrigin != nil {
		return abstractOrigin.ByteSize()
	}

	if typ := n.Type(); typ != nil {
		return typ.ByteSize()
	}

	return 0
}

func (n *node) Location() ([]op.Operation, error) {
	ops := n.rawLocation()
	if ops == nil {
		return nil, nil
	}

	return op.Parse(ops)
}

func (n *node) LocationList() (*loclist, error) {
	loclistOffset := n.entry.Val(dwarf.AttrLocation)
	if loclistOffset == nil {
		return nil, nil
	}

	offset, ok := loclistOffset.(uint64)
	if !ok {
		return nil, nil
	}

	return n.tree.llt.Loclist(int(offset))
}

func (n *node) Type() *node {
	typ := n.entry.Val(dwarf.AttrType)
	if typ != nil {
		typeEntry, ok := n.tree.index[typ.(dwarf.Offset)]
		if !ok {
			return nil
		}

		return typeEntry

	}

	abstractOrigin := n.AbstractOrigin()
	if abstractOrigin != nil {
		return abstractOrigin.Type()
	}

	return nil
}

func (n *node) FileCol() string {
	fileIndex := n.entry.Val(dwarf.AttrDeclFile)
	if fileIndex == nil {
		abstractOrigin := n.AbstractOrigin()
		if abstractOrigin != nil {
			return abstractOrigin.FileCol()
		}

		return ""
	}
	file := n.tree.files[fileIndex.(int64)]

	fileLine := n.entry.Val(dwarf.AttrDeclLine)
	if fileLine != nil {
		fileCol := n.entry.Val(dwarf.AttrDeclColumn)
		if fileCol != nil {
			return fmt.Sprintf("%s:%d:%d", file.Name, fileLine.(int64), fileCol.(int64))
		}

		return fmt.Sprintf("%s:%d", file.Name, fileLine.(int64))
	}

	return file.Name
}

func visitPrefixOrder(n *node, f func(*node)) {
	f(n)
	for _, c := range n.children {
		visitPrefixOrder(c, f)
	}
}

func DWARF(f *elf.File) (*dwarf.Data, error) {
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

	// There are many DWARF sections, but these are the ones
	// the debug/dwarf package started with.
	var dat = map[string][]byte{"abbrev": nil, "info": nil, "str": nil, "line": nil, "ranges": nil}
	for _, s := range f.Sections {
		suffix := dwarfSuffix(s)
		if suffix == "" {
			continue
		}
		if _, ok := dat[suffix]; !ok {
			continue
		}
		b, err := s.Data()
		if err != nil {
			return nil, err
		}
		dat[suffix] = b
	}

	d, err := dwarf.New(dat["abbrev"], nil, nil, dat["info"], dat["line"], nil, dat["ranges"], dat["str"])
	if err != nil {
		return nil, err
	}

	// Look for DWARF4 .debug_types sections and DWARF5 sections.
	for i, s := range f.Sections {
		suffix := dwarfSuffix(s)
		if suffix == "" {
			continue
		}
		if _, ok := dat[suffix]; ok {
			// Already handled.
			continue
		}

		b, err := s.Data()
		if err != nil {
			return nil, err
		}

		if suffix == "types" {
			if err := d.AddTypes(fmt.Sprintf("types-%d", i), b); err != nil {
				return nil, err
			}
		} else {
			if err := d.AddSection(".debug_"+suffix, b); err != nil {
				return nil, err
			}
		}
	}

	return d, nil
}

type loclistHdr struct {
	unitLength          uint64
	version             uint16
	addrSize            uint8
	segmentSelectorSize uint8
	offsetEntryCount    uint32
}

type loclistTable struct {
	hdr     loclistHdr
	offsets []uint64
	raw     []byte
}

type loclistDescriptorCode byte

const (
	DW_LLE_end_of_list   loclistDescriptorCode = 0x00
	DW_LLE_base_addressx loclistDescriptorCode = 0x01
	// DW_LLE_startx_endx      loclistDescriptor = 0x02
	// DW_LLE_startx_length    loclistDescriptor = 0x03
	DW_LLE_offset_pair loclistDescriptorCode = 0x04
	// DW_LLE_default_location loclistDescriptor = 0x05
	// DW_LLE_base_address     loclistDescriptor = 0x06
	// DW_LLE_start_end        loclistDescriptor = 0x07
	DW_LLE_start_length loclistDescriptorCode = 0x08
)

type loclistEntry interface {
	_loclistEntry()
}

type lleBaseAddressX struct {
	debugAddrIndex uint64
}

func (d lleBaseAddressX) _loclistEntry() {}

type lleOffsetPair struct {
	offset1 uint64
	offset2 uint64
	ops     []op.Operation
}

func (d lleOffsetPair) _loclistEntry() {}

type lleStartLength struct {
	start  uint64
	length uint64
}

func (d lleStartLength) _loclistEntry() {}

type loclist struct {
	entries []loclistEntry
}

func (l *loclistTable) Dump() {
	for i, offset := range l.offsets {
		fmt.Printf("Loclist %d (offset %#x):\n", i, offset)
		loclist, err := l.Loclist(i)
		if err != nil {
			fmt.Printf("  <error parsing loclist: %v>\n", err)
			continue
		}
		for _, entry := range loclist.entries {
			switch e := entry.(type) {
			case lleBaseAddressX:
				fmt.Printf("  DW_LLE_base_addressx: debug_addr index %d\n", e.debugAddrIndex)
			case lleOffsetPair:
				fmt.Printf("  DW_LLE_offset_pair: offset1 %#x, offset2 %#x, ops %v\n", e.offset1, e.offset2, e.ops)
			case lleStartLength:
				fmt.Printf("  DW_LLE_start_length: start %#x, length %#x\n", e.start, e.length)
			default:
				fmt.Printf("  unknown entry type %T\n", e)
			}
		}
	}
}

func (l *loclistTable) Loclist(i int) (*loclist, error) {
	if i >= len(l.offsets) {
		return nil, fmt.Errorf("loclist index out of range")
	}

	offset := l.offsets[i]
	r := bytes.NewReader(l.raw[offset:])

	var list loclist

loop:
	for {
		descriptorByte, err := r.ReadByte()
		if err != nil {
			return nil, err
		}

		var entry loclistEntry
		switch loclistDescriptorCode(descriptorByte) {
		case DW_LLE_end_of_list:
			break loop
		case DW_LLE_base_addressx:
			var baseAddrX lleBaseAddressX
			baseAddrX.debugAddrIndex, _ = leb128.DecodeUnsigned(r)
			entry = baseAddrX
		case DW_LLE_offset_pair:
			var offsetPair lleOffsetPair
			offsetPair.offset1, _ = leb128.DecodeUnsigned(r)
			offsetPair.offset2, _ = leb128.DecodeUnsigned(r)

			opsLen, _ := leb128.DecodeUnsigned(r)
			opsData := make([]byte, opsLen)
			if _, err := r.Read(opsData); err != nil {
				return nil, err
			}

			ops, err := op.Parse(opsData)
			if err != nil {
				return nil, err
			}
			offsetPair.ops = ops

			entry = offsetPair
		default:
			return nil, fmt.Errorf("unsupported loclist descriptor code: %x", descriptorByte)
		}

		list.entries = append(list.entries, entry)
	}

	return &list, nil
}

func newLoclistTable(f *elf.File) (*loclistTable, error) {
	sec := f.Section(".debug_loclists")
	if sec == nil {
		return nil, nil
	}

	if f.Class != elf.ELFCLASS64 {
		return nil, fmt.Errorf("unexpected 32-bit ELF file")
	}

	b, err := sec.Data()
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(b)

	var (
		list   loclistTable
		ulen   uint32
		_32bit bool
	)

	if err := binary.Read(r, f.ByteOrder, &ulen); err != nil {
		return nil, err
	}
	if ulen == 0xffffffff {
		var ulen64 uint64
		if err := binary.Read(r, f.ByteOrder, &ulen64); err != nil {
			return nil, err
		}
		list.hdr.unitLength = ulen64
		_32bit = false
	} else {
		list.hdr.unitLength = uint64(ulen)
		_32bit = true
	}

	if err := binary.Read(r, f.ByteOrder, &list.hdr.version); err != nil {
		return nil, err
	}
	if err := binary.Read(r, f.ByteOrder, &list.hdr.addrSize); err != nil {
		return nil, err
	}
	if err := binary.Read(r, f.ByteOrder, &list.hdr.segmentSelectorSize); err != nil {
		return nil, err
	}
	if err := binary.Read(r, f.ByteOrder, &list.hdr.offsetEntryCount); err != nil {
		return nil, err
	}

	if _32bit {
		list.raw = b[12:]
	} else {
		list.raw = b[20:]
	}

	if _32bit {
		offsets := make([]uint32, list.hdr.offsetEntryCount)
		if err := binary.Read(r, f.ByteOrder, &offsets); err != nil {
			return nil, err
		}
		for _, o := range offsets {
			list.offsets = append(list.offsets, uint64(o))
		}
	} else {
		if err := binary.Read(r, f.ByteOrder, &list.offsets); err != nil {
			return nil, err
		}
	}

	return &list, nil
}
