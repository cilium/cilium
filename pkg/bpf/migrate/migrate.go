// Copyright 2021 Authors of Cilium
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

package migrate

import (
	"fmt"
	"log/syslog"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	statePending = "pending"
	utimeNow     = (1 << 30) - 1
)

var (
	fsBase      string
	timeSpecNow = syscall.Timespec{
		Sec:  0,
		Nsec: utimeNow,
	}
	nilTimeSpecArg = []syscall.Timespec{timeSpecNow, timeSpecNow}
)

func init() {
	fsBase = filepath.Join(defaults.DefaultMapRoot, "/tc/globals")
}

// Start starts the maps migration process for a specific elf file's
// maps. It returns true if it created a pending file and false if it
// didn't do anything (i.e. the pinned/old map is the same as the new
// one).
// The "syslogger" argument is optional
func Start(pathName string, syslogger *syslog.Writer) (bool, error) {
	coll, err := ebpf.LoadCollection(pathName)
	if err != nil {
		return false, err
	}
	var moved bool
	for n, m := range coll.Maps {
		mv, err := bpfPending(n, m, syslogger)
		if err != nil {
			return moved, err
		}
		if mv {
			moved = true
		}
	}
	return moved, nil
}

func bpfPending(name string, m *ebpf.Map, syslogger *syslog.Writer) (bool, error) {
	file := fmt.Sprintf("%s/%s", fsBase, name)
	_, err := os.Stat(file)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("cannot stat node %q", file)
	}
	pinned, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		return false, err
	}
	if pinned.Type() == m.Type() &&
		pinned.KeySize() == m.KeySize() &&
		pinned.ValueSize() == m.ValueSize() &&
		pinned.Flags() == m.Flags() &&
		pinned.MaxEntries() == m.MaxEntries() {
		return false, nil
	}
	dest := fmt.Sprintf("%s:%s", file, statePending)
	if syslogger != nil {
		syslogger.Warning(fmt.Sprintf("Property mismatch in %s, migrating node to %s!\n", file, dest))
	}
	err = syscall.UtimesNano(file, nilTimeSpecArg)
	if err != nil {
		return false, fmt.Errorf("could not update timestamp of %q", file)
	}
	err = os.Rename(file, dest)
	if err != nil {
		return false, err
	}
	return true, nil
}

// Finish finishes migrating the maps of a specific elf file's maps.
func Finish(pathName string, exit int, syslogger *syslog.Writer) error {
	coll, err := ebpf.LoadCollection(pathName)
	if err != nil {
		return err
	}
	for n := range coll.Maps {
		err := bpfFinalize(n, exit, syslogger)
		if err != nil {
			return err
		}
	}
	return nil
}

func bpfFinalize(name string, exit int, syslogger *syslog.Writer) error {
	file := fmt.Sprintf("%s/%s:%s", fsBase, name, statePending)
	_, err := os.Stat(file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cannot stat node %q", file)
	}
	if exit != 0 {
		dest := fmt.Sprintf("%s/%s", fsBase, name)
		if syslogger != nil {
			syslogger.Warning(fmt.Sprintf("Restoring migrated node %s into %s due to bad exit.\n", file, dest))
		}
		err = syscall.UtimesNano(file, nilTimeSpecArg)
		if err != nil {
			return fmt.Errorf("could not update timestamp of %q", file)
		}
		err := unix.Renameat2(unix.AT_FDCWD, file, unix.AT_FDCWD, dest, 1)
		if err != nil {
			return fmt.Errorf("could not rename %q to %q", file, dest)
		}
		return nil
	}
	if syslogger != nil {
		syslogger.Warning(fmt.Sprintf("Unlinking migrated node %s due to good exit.\n", file))
	}
	return syscall.Unlink(file)
}

// type bpfELFCtx struct {
// 	File      *elf.File
// 	Maps      *elf.Section
// 	MapSecIdx elf.SectionIndex
// }

// type bpfELfMap struct {
// 	typ       uint32
// 	keySize   uint32
// 	valueSize uint32
// 	maxElem   uint32
// 	flags     uint32
// 	id        uint32
// 	pinning   uint32
// 	innerFD   uint32
// 	innerIdx  uint32
// }

// State migrate elf object map state, syslogger is not a required argument.
// func State(pathName string, finalize bool, exit int, syslogger *syslog.Writer) error {
// 	var err error
// 	ctx := new(bpfELFCtx)
// 	ctx.File, err = elf.Open(pathName)
// 	if err != nil {
// 		return err
// 	}
// 	defer ctx.File.Close()

// 	if ctx.File.Type != elf.ET_REL ||
// 		(ctx.File.Machine != elf.EM_NONE && ctx.File.Machine != elf.EM_BPF) ||
// 		ctx.File.Version != elf.EV_CURRENT {
// 		return fmt.Errorf("ELF format error, ELF file is not for eBPF")
// 	}
// 	if isBE := isBigEndian(); isBE && ctx.File.ByteOrder.String() != "BigEndian" {
// 		return fmt.Errorf("host is big endian, eBPF object is little endian")
// 	} else if !isBE && ctx.File.ByteOrder.String() != "LittleEndian" {
// 		return fmt.Errorf("host is little endian, eBPF object is big endian")
// 	}
// 	var hasMaps bool
// 	for i, sec := range ctx.File.Sections {
// 		if sec.Type == elf.SHT_PROGBITS && sec.Name == "maps" {
// 			ctx.Maps = sec
// 			ctx.MapSecIdx = elf.SectionIndex(i)
// 			hasMaps = true
// 		}
// 	}
// 	if !hasMaps {
// 		return fmt.Errorf("%q elf object does not have a maps section", pathName)
// 	}
// 	maps, err := bpfFetchMaps(ctx)
// 	if err != nil {
// 		return err
// 	}
// 	for name, m := range maps {
// 		if finalize {
// 			err := bpfFinalize(name, exit, syslogger)
// 			if err != nil {
// 				return err
// 			}
// 		} else {
// 		}
// 	}
// 	return nil
// }

// func bpfFetchMaps(ctx *bpfELFCtx) (map[string]*bpfELfMap, error) {
// 	syms, err := ctx.File.Symbols()
// 	if err != nil {
// 		return nil, err
// 	}
// 	var (
// 		nSym       int
// 		mapSymbols = make(map[uint64]elf.Symbol)
// 	)
// 	for _, sym := range syms {
// 		if elf.ST_BIND(sym.Info) != elf.STB_GLOBAL ||
// 			elf.ST_TYPE(sym.Info) == elf.STT_NOTYPE ||
// 			elf.ST_TYPE(sym.Info) == elf.STT_OBJECT ||
// 			sym.Section != ctx.MapSecIdx {
// 			continue
// 		}
// 		mapSymbols[sym.Value] = sym
// 		nSym++
// 	}
// 	if nSym == 0 || nSym > 64 {
// 		return nil, fmt.Errorf("%d maps not supported in current map section", nSym)
// 	}
// 	if ctx.Maps.Size%uint64(nSym) != 0 {
// 		return nil, fmt.Errorf("map section map descriptors are not of equal size")
// 	}

// 	var (
// 		size = ctx.Maps.Size / uint64(nSym)
// 		r    = bufio.NewReader(ctx.Maps.Open())
// 		maps = make(map[string]*bpfELfMap)
// 		bo   = ctx.File.ByteOrder
// 	)
// 	for i, offset := 0, uint64(0); i < nSym; i, offset = i+1, offset+size {
// 		mapSym, ok := mapSymbols[offset]
// 		if !ok {
// 			return nil, fmt.Errorf("maps section missing symbol for map at offset %d", offset)
// 		}
// 		name := mapSym.Name
// 		if maps[name] != nil {
// 			return nil, fmt.Errorf("maps section has two map entries for %q", name)
// 		}
// 		lr := io.LimitReader(r, int64(size))
// 		spec := ebpf.MapSpec{
// 			Name: ebpf.SanitizeName(name, -1),
// 		}
// 		var pinning uint32
// 		switch {
// 		case binary.Read(lr, bo, &spec.Type) != nil:
// 			return nil, fmt.Errorf("map %q: missing type", name)
// 		case binary.Read(lr, bo, &spec.KeySize) != nil:
// 			return nil, fmt.Errorf("map %q: missing key size", name)
// 		case binary.Read(lr, bo, &spec.ValueSize) != nil:
// 			return nil, fmt.Errorf("map %q: missing value size", name)
// 		case binary.Read(lr, bo, &spec.MaxEntries) != nil:
// 			return nil, fmt.Errorf("map %q: missing max entries", name)
// 		case binary.Read(lr, bo, &spec.Flags) != nil:
// 			return nil, fmt.Errorf("map %q: missing flags", name)
// 		case binary.Read(lr, bo, &pinning) != nil:
// 			return nil, fmt.Errorf("map %q: missing pinning", name)
// 		}
// 		io.Copy(io.Discard, lr)
// 		// if pinning != PIN_GLOBAL_NS
// 		// cf https://elixir.bootlin.com/linux/latest/source/samples/bpf/tc_l2_redirect_kern.c#L22
// 		if pinning != 2 {
// 			continue
// 		}
// 		maps[mapSym.Name] = &spec
// 	}
// 	return maps, nil
// }

// func bpfPending(ctx *bpfELFCtx, m *bpfELfMap, name string, exit int, syslogger *syslog.Writer) error {
// 	file := fmt.Sprintf("%s/%s", fsBase, name)
// 	_, err := os.Stat(file)
// 	if err != nil {
// 		if os.IsNotExist(err) {
// 			return nil
// 		}
// 		return fmt.Errorf("cannot stat node %q", file)
// 	}
// 	pinned, err := ebpf.LoadPinnedMap(file, nil)
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

// func isBigEndian() bool {
// 	i := int(0x1)
// 	bs := (*[int(unsafe.Sizeof(i))]byte)(unsafe.Pointer(&i))
// 	return bs[0] == 0
// }
