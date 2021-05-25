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

// +build privileged_tests

package bpfprogtester

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type ct4GlobalMap map[ctmap.CtKey4Global]ctmap.CtEntry

func ct4TcpMapFromBPF(ebpfMap *ebpf.Map) (ct4GlobalMap, error) {
	var key ctmap.CtKey4Global
	var val ctmap.CtEntry

	ret := make(ct4GlobalMap)
	iter := ebpfMap.Iterate()
	for iter.Next(&key, &val) {
		ret[key] = val
	}

	if err := iter.Err(); err != nil {
		return ret, fmt.Errorf("Error iterating map: %v", err)
	}

	return ret, nil
}

func mapDeleteAll(m *ebpf.Map) error {
	for {
		key, err := m.NextKeyBytes(nil)
		if err != nil {
			return err
		}
		if key == nil {
			break
		}

		if err := m.Delete(key); err != nil {
			return err
		}
	}

	return nil
}

func testNop(spec *ebpf.Collection) error {
	prog := spec.Programs["test_nop"]
	if prog == nil {
		return errors.New("did not find test_nop program")
	}

	packetIn := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(packetIn, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{1, 0, 0, 3, 0, 10},
			DstMAC:       net.HardwareAddr{1, 0, 0, 3, 0, 20},
			EthernetType: layers.EthernetTypeIPv4,
		},
	)

	bpfRet, bufOut, err := prog.Test(packetIn.Bytes())
	if err != nil {
		return fmt.Errorf("test run failed: %v", err)
	}

	if bpfRet != 0 { // CT_ACT_OK
		return errors.New("unexpected return value")
	}

	if !reflect.DeepEqual(bufOut, packetIn.Bytes()) {
		return errors.New("unexpected data modification")
	}

	return nil
}

func testMap(spec *ebpf.Collection) error {
	prog := spec.Programs["test_map"]
	if prog == nil {
		return errors.New("did not find test_map program")
	}

	bpfCtMap := spec.Maps["test_cilium_ct_tcp4_65535"]
	if bpfCtMap == nil {
		return errors.New("did not find test_cilium_ct_tcp4_65535 map")
	}

	mapBefore, err := ct4TcpMapFromBPF(bpfCtMap)
	if err != nil {
		return fmt.Errorf("ct4TcpMapFromBPF failed: %v", err)
	}
	if len(mapBefore) != 0 {
		return errors.New("BPF CT map is not empty")
	}

	packetIn := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(packetIn, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{1, 0, 0, 3, 0, 10},
			DstMAC:       net.HardwareAddr{1, 0, 0, 3, 0, 20},
			EthernetType: layers.EthernetTypeIPv4,
		},
	)

	bpfRet, bufOut, err := prog.Test(packetIn.Bytes())
	if err != nil {
		return fmt.Errorf("test run failed: %v", err)
	}

	if bpfRet != 0 { // CT_ACT_OK
		return errors.New("unexpected return value")
	}

	if !reflect.DeepEqual(bufOut, packetIn.Bytes()) {
		return errors.New("unexpected data modification")
	}

	keyExpected := ctmap.CtKey4Global{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{1, 1, 1, 1},
				DestAddr:   types.IPv4{1, 1, 1, 2},
				SourcePort: byteorder.HostToNetwork(uint16(1001)).(uint16),
				DestPort:   byteorder.HostToNetwork(uint16(1002)).(uint16),
				NextHeader: 0,
				Flags:      0,
			},
		},
	}
	valExecpted := ctmap.CtEntry{
		TxPackets: 1000,
		RxPackets: 1000,
	}
	mapExpected := ct4GlobalMap{
		keyExpected: valExecpted,
	}

	mapAfter, err := ct4TcpMapFromBPF(bpfCtMap)
	if err != nil {
		return fmt.Errorf("ct4TcpMapFromBPF failed: %v", err)
	}

	if !reflect.DeepEqual(mapAfter, mapExpected) {
		return errors.New("resulting BPF CT map is not equal to expected")
	}

	mapDeleteAll(bpfCtMap)
	return nil
}

// NB: Currently, cilium/ebpf cannot deal with non-zero bpf_elf_map fields
// after ->flags. We don't really need them for our tests, so we zero them out
// for now. Once support is added to cilium/ebpf for these fields, we can
// remove this.
func patchElf(fname string, fnameOut string) error {
	osF, err := os.Open(fname)
	if err != nil {
		return err
	}
	defer osF.Close()

	elfF, err := elf.NewFile(osF)
	if err != nil {
		return err
	}
	defer elfF.Close()

	syms, err := elfF.Symbols()
	if err != nil {
		return err
	}

	mapSectionsOff := map[elf.SectionIndex]uint64{}
	for secIdx, sec := range elfF.Sections {
		if strings.HasPrefix(sec.Name, "maps") {
			mapSectionsOff[elf.SectionIndex(secIdx)] = sec.Offset
		}
	}

	mapSymbols := map[string]uint64{}
	for _, sym := range syms {
		secOff, ok := mapSectionsOff[sym.Section]
		if !ok {
			continue
		}

		//  This is what the current map structure looks from bpf side, so we should expect the size to be 9*4=36
		//
		//  struct bpf_elf_map {
		//  	__u32 type;
		//  	__u32 size_key;
		//  	__u32 size_value;
		//  	__u32 max_elem;
		//  	__u32 flags;
		//  	__u32 id;
		//  	__u32 pinning;
		//  	__u32 inner_id;
		//  	__u32 inner_idx;
		//  };
		expectedMapSize := uint64(9 * 4)
		if sym.Size != expectedMapSize {
			log.WithFields(log.Fields{
				"expected": expectedMapSize,
				"actual":   sym.Size,
			}).Fatal("invalid size")
		}
		mapSymbols[sym.Name] = sym.Value + secOff
	}

	outF, err := os.Create(fnameOut)
	if err != nil {
		log.WithFields(log.Fields{
			"filename": fnameOut,
		}).Fatalf("error creating file: %v", err)
	}
	if err = outF.Truncate(0); err != nil {
		log.WithFields(log.Fields{
			"filename": fnameOut,
		}).Fatalf("error truncating file: %v", err)
	}
	defer outF.Close()

	if _, err = io.Copy(outF, osF); err != nil {
		log.WithFields(log.Fields{
			"filename": fnameOut,
		}).Fatalf("error copying file: %v", err)
	}

	zero := [4 * 4]byte{}
	for symName, symOff := range mapSymbols {
		idOff := symOff + (5 * 4)
		_, err = outF.WriteAt(zero[:], int64(idOff))
		if err != nil {
			log.WithFields(log.Fields{
				"filename": fnameOut,
			}).Fatalf("error patching file: %v", err)
		}
		log.WithFields(log.Fields{
			"map": symName,
		}).Debug("zeroed last fields")
	}

	return nil

}

func dumpDebugMessages(eventsReader *perf.Reader) error {
	fmt.Printf("Log Messages:\n")
	for {
		record, err := eventsReader.Read()
		if err != nil {
			return fmt.Errorf("error reading event buffer: %v\n", err)
		}

		dm := monitor.DebugMsg{}
		reader := bytes.NewReader(record.RawSample)
		if err := binary.Read(reader, byteorder.Native, &dm); err != nil {
			return fmt.Errorf("Error while parsing debug message: %v\n", err)
		}

		// special record values set from our bpf programs to mark their termination
		if dm.SubType == monitor.DbgUnspec && dm.Arg1 == 0xe3d && dm.Arg2 == 0xe3d {
			break
		}
		dm.Dump("")
	}

	return nil
}

func testCt4Rst(spec *ebpf.Collection) error {
	eventsReader, err := perf.NewReader(spec.Maps["test_events_map"], 1024*4096)
	if err != nil {
		log.WithError(err).Fatal("Cannot initialise BPF perf ring buffer sockets")
	}
	defer func() {
		eventsReader.Close()
	}()

	packetSyn := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(packetSyn, gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{1, 0, 0, 3, 0, 10},
			DstMAC:       net.HardwareAddr{1, 0, 0, 3, 0, 20},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			SrcIP:    net.IP{10, 3, 0, 10},
			DstIP:    net.IP{10, 3, 0, 20},
			Protocol: layers.IPProtocolTCP,
			IHL:      5,
		},
		&layers.TCP{
			SrcPort:    3010,
			DstPort:    3020,
			DataOffset: 5,
			SYN:        true,
		},
		gopacket.Payload([]byte("pizza! :-)")),
	)

	packetRst := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(packetRst, gopacket.SerializeOptions{},
		&layers.Ethernet{
			DstMAC:       net.HardwareAddr{1, 0, 0, 3, 0, 10},
			SrcMAC:       net.HardwareAddr{1, 0, 0, 3, 0, 20},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			DstIP:    net.IP{10, 3, 0, 10},
			SrcIP:    net.IP{10, 3, 0, 20},
			Protocol: layers.IPProtocolTCP,
			IHL:      5,
		},
		&layers.TCP{
			DstPort:    3010,
			SrcPort:    3020,
			DataOffset: 5,
			RST:        true,
		},
		gopacket.Payload([]byte("pizza! :-)")),
	)

	bpfCtMap := spec.Maps["test_cilium_ct_tcp4_65535"]

	// First Packet: SYN
	prog1 := spec.Programs["test_ct4_rst1"]
	if prog1 == nil {
		return errors.New("did not find test_ct4_rst1 program")
	}
	bpfRet, bufOut, err := prog1.Test(packetSyn.Bytes())
	if err != nil {
		return fmt.Errorf("test run failed: %v", err)
	}
	if bpfRet != 0 { // CT_ACT_OK
		return errors.New("unexpected return value")
	}
	if !reflect.DeepEqual(bufOut, packetSyn.Bytes()) {
		return errors.New("unexpected data modification")
	}
	if err := dumpDebugMessages(eventsReader); err != nil {
		return fmt.Errorf("dumpDebugMessages failed: %v", err)
	}
	bpfCt, err := ct4TcpMapFromBPF(bpfCtMap)
	if err != nil {
		return fmt.Errorf("ct4TcpMapFromBPF failed: %v", err)
	}
	fmt.Printf("CT Entries:\n")
	for key, val := range bpfCt {
		fmt.Printf(" key=%s val=%s", &key, &val)
	}

	now, err := bpf.GetMtime()
	if err != nil {
		return errors.New("GetMtime failed")
	}
	// Second Packet: RST
	prog2 := spec.Programs["test_ct4_rst2"]
	if prog2 == nil {
		return errors.New("did not find test_ct4_rst2 program")
	}
	bpfRet, bufOut, err = prog2.Test(packetRst.Bytes())
	if err != nil {
		return fmt.Errorf("test run failed: %v", err)
	}
	if err := dumpDebugMessages(eventsReader); err != nil {
		return fmt.Errorf("dumpDebugMessages failed: %v", err)
	}
	bpfCt, err = ct4TcpMapFromBPF(bpfCtMap)
	if err != nil {
		return fmt.Errorf("ct4TcpMapFromBPF failed: %v", err)
	}
	fmt.Printf("CT Entries:\n")
	for key, val := range bpfCt {
		fmt.Printf(" key=%s val=%s", key.ToHost(), &val)
	}
	if bpfRet != 0 { // CT_ACT_OK
		return errors.New("unexpected return value")
	}
	if !reflect.DeepEqual(bufOut, packetRst.Bytes()) {
		return errors.New("unexpected data modification")
	}

	key := ctmap.CtKey4Global{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{10, 3, 0, 20},
				DestAddr:   types.IPv4{10, 3, 0, 10},
				SourcePort: byteorder.HostToNetwork(uint16(3010)).(uint16),
				DestPort:   byteorder.HostToNetwork(uint16(3020)).(uint16),
				NextHeader: 6,
				Flags:      0,
			},
		},
	}
	val := bpfCt[key]
	expires := (val.Lifetime - uint32(now/1000000000))
	fmt.Printf("Entry expires in %ds\n", expires)
	if expires > 10 {
		return errors.New("Expiration is >10s even if RST flag was set")
	}

	return nil
}

// TestCt checks connection tracking
func TestCt(t *testing.T) {

	objDir := ".."
	fname := path.Join(objDir, "bpf_ct_tests.o")
	fnamePatched := path.Join(objDir, "bpf_ct_tests_patched.o")
	err := patchElf(fname, fnamePatched)
	if err != nil {
		t.Fatal(err)
	}

	coll, err := ebpf.LoadCollection(fnamePatched)
	if err != nil {
		t.Fatalf("failed to load %s: %s", fnamePatched, err)
	}

	t.Run("Nop test", func(t *testing.T) {
		err := testNop(coll)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}
	})

	t.Run("Map test", func(t *testing.T) {
		err := testMap(coll)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}
	})

	t.Run("RST handling", func(t *testing.T) {
		err := testCt4Rst(coll)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}
	})
}

func TestMain(m *testing.M) {
	lim := unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		log.Fatalf("setrlimit: %v", err)
	}
	os.Exit(m.Run())
}
