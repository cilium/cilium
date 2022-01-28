// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

//go:build privileged_tests
// +build privileged_tests

package bpfprogtester

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
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
				SourcePort: byteorder.HostToNetwork16(1001),
				DestPort:   byteorder.HostToNetwork16(1002),
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

func dumpDebugMessages(eventsReader *perf.Reader, linkCache getters.LinkGetter) error {
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
		dm.Dump("", linkCache)
	}

	return nil
}

func testCt4Rst(spec *ebpf.Collection) error {
	eventsReader, err := perf.NewReader(spec.Maps["test_events_map"], 1024*4096)
	if err != nil {
		logrus.WithError(err).Fatal("Cannot initialise BPF perf ring buffer sockets")
	}
	defer func() {
		eventsReader.Close()
	}()

	linkCache := link.NewLinkCache()
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
	if err := dumpDebugMessages(eventsReader, linkCache); err != nil {
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
	if err := dumpDebugMessages(eventsReader, linkCache); err != nil {
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
				SourcePort: byteorder.HostToNetwork16(3010),
				DestPort:   byteorder.HostToNetwork16(3020),
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

func modifyMapSpecs(spec *ebpf.CollectionSpec) {
	for _, m := range spec.Maps {
		// Clear pinning flag on all Maps, keep this test self-contained.
		m.Pinning = 0

		// Drain Extra section of legacy bpf_elf_map definitions. The library
		// rejects any bytes left over in Extra on load.
		if m.Extra != nil {
			io.Copy(io.Discard, m.Extra)
		}
	}
}

// TestCt checks connection tracking
func TestCt(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec("../bpf_ct_tests.o")
	if err != nil {
		t.Fatalf("failed to load spec: %s", err)
	}

	modifyMapSpecs(spec)

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load collection: %s", err)
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
		logrus.Fatalf("setrlimit: %v", err)
	}
	os.Exit(m.Run())
}
