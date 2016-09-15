//
// Copyright 2016 Authors of Cilium
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
//
package lbmap

/*
#cgo CFLAGS: -I../include
#include <linux/bpf.h>
#include <sys/resource.h>
*/
import "C"

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"unsafe"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/bpf"
	"github.com/cilium/cilium/common/types"

	"github.com/codegangsta/cli"
)

var (
	ipv4 bool
)

const (
	maxEntries = 65536
)

type LB6Key struct {
	Address types.IPv6
	Port    uint16
	Slave   uint16
}

func (k LB6Key) GetPtr() unsafe.Pointer {
	return unsafe.Pointer(&k)
}

type LB4Key struct {
	Address types.IPv4
	Port    uint16
	Slave   uint16
}

func (k LB4Key) GetPtr() unsafe.Pointer {
	return unsafe.Pointer(&k)
}

type LB6Service struct {
	Address types.IPv6
	Port    uint16
	Count   uint16
}

type LB4Service struct {
	Address types.IPv4
	Port    uint16
	Count   uint16
	RevNAT  uint16
}

func (s *LB4Service) GetPtr() unsafe.Pointer {
	return unsafe.Pointer(s)
}

type RevNatKey uint16

func NewRevNatKey(value uint16) RevNatKey {
	// The key is in network byte order
	return RevNatKey(common.Swab16(value))
}

func (k RevNatKey) GetPtr() unsafe.Pointer {
	return unsafe.Pointer(&k)
}

type LB6ReverseNAT struct {
	Address types.IPv6
	Port    uint16
}

type LB4ReverseNAT struct {
	Address types.IPv4
	Port    uint16
}

type LBMap struct {
	fd int
}

func parseUint16(ctx *cli.Context, argn int) uint16 {
	tmp, err := strconv.ParseUint(ctx.Args().Get(argn), 0, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid argument: %s\n", err)
		printUsageAndExit(ctx)
	}

	return uint16(tmp)
}

func servicesMap() *bpf.Map {
	if ipv4 {
		return bpf.NewMap(common.BPFCiliumMaps+"/cilium_lb4_services",
			bpf.MapTypeHash,
			int(unsafe.Sizeof(LB4Key{})),
			int(unsafe.Sizeof(LB4Service{})),
			maxEntries)
	} else {
		return bpf.NewMap(common.BPFCiliumMaps+"/cilium_lb6_services",
			bpf.MapTypeHash,
			int(unsafe.Sizeof(LB6Key{})),
			int(unsafe.Sizeof(LB6Service{})),
			maxEntries)
	}
}

func revNATMap() *bpf.Map {
	if ipv4 {
		return bpf.NewMap(common.BPFCiliumMaps+"/cilium_lb4_reverse_nat",
			bpf.MapTypeHash,
			int(unsafe.Sizeof(uint16(0))),
			int(unsafe.Sizeof(LB4ReverseNAT{})),
			maxEntries)
	} else {
		return bpf.NewMap(common.BPFCiliumMaps+"/cilium_lb6_reverse_nat",
			bpf.MapTypeHash,
			int(unsafe.Sizeof(uint16(0))),
			int(unsafe.Sizeof(LB6ReverseNAT{})),
			maxEntries)
	}
}

func printUsageAndExit(ctx *cli.Context) {
	fmt.Fprintf(os.Stderr, "Usage: %s %s %s\n", ctx.App.Name, ctx.Command.Name,
		ctx.Command.ArgsUsage)
	os.Exit(2)
}

var (
	// CliCommand is the command that will be used in cilium-net main program.
	CliCommand cli.Command
)

func init() {
	CliCommand = cli.Command{
		Name:  "lb",
		Usage: "configure load balancer",
		Flags: []cli.Flag{
			cli.BoolFlag{
				Destination: &ipv4,
				Name:        "ipv4, 4",
				Usage:       "Apply setting to IPv4 LB",
			},
		},
		Subcommands: []cli.Command{
			{
				Name:      "init",
				Usage:     "initialize load balancer",
				ArgsUsage: "",
				Action:    lbInitialize,
			},
			{
				Name:   "create-services-map",
				Usage:  "creates the services map",
				Action: lbCreateServices,
			},
			{
				Name:   "create-rev-nat-map",
				Usage:  "creates the reverse NAT map",
				Action: lbCreateReverseNAT,
			},
			{
				Name:   "dump-service",
				Usage:  "dumps map present on the given <map file>",
				Action: lbDumpServices,
			},
			{
				Name:   "dump-rev-nat",
				Usage:  "dumps map present on the given <map file>",
				Action: lbDumpReverseNAT,
			},
			{
				Name:      "get-service",
				Usage:     "Lookup LB service",
				ArgsUsage: "<ipv6 addr> <dport> <slave index>",
				Action:    lbLookupService,
			},
			{
				Name:      "get-rev-nat",
				Usage:     "gets key's value of the given <map file>",
				ArgsUsage: "<reverse NAT key>",
				Action:    lbLookupReverseNAT,
			},
			{
				Name:      "update-service",
				Usage:     "updates key's value of the given <map file>",
				ArgsUsage: "<address> <port> <slave> <count> <reverse nat key> <slave address> <port>",
				Action:    lbUpdateService,
			},
			{
				Name:      "update-rev-nat",
				Usage:     "update LB reverse NAT table",
				ArgsUsage: "<revarse NAT key> <address> <port>",
				Action:    lbUpdateReverseNAT,
			},
			{
				Name:      "delete-service",
				Action:    lbDeleteService,
				ArgsUsage: "<address> <port> <slave-index>",
			},
			{
				Name:      "delete-rev-nat",
				Action:    lbDeleteReverseNAT,
				ArgsUsage: "<reverse NAT key>",
			},
		},
	}
}

func lbInitialize(ctx *cli.Context) {
	if len(ctx.Args()) != 2 {
		printUsageAndExit(ctx)
	}

	globalsDir := filepath.Join(common.CiliumPath, "globals")
	if err := os.MkdirAll(globalsDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Could not create runtime directory %s: %s", globalsDir, err)
		os.Exit(1)
	}

	if err := os.Chdir(common.CiliumPath); err != nil {
		fmt.Fprintf(os.Stderr, "Could not change to runtime directory %s: \"%s\"",
			common.CiliumPath, err)
		os.Exit(1)
	}

	f, err := os.Create("./globals/lb_config.h")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create lb_config.h: %s\n", err)
		os.Exit(1)
	}

	fw := bufio.NewWriter(f)

	fw.Flush()
	f.Close()
}

func lbCreateServices(ctx *cli.Context) {
	_, err := servicesMap().OpenOrCreate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create map: %s\n", err)
		os.Exit(1)
	}
}

func lbCreateReverseNAT(ctx *cli.Context) {
	_, err := revNATMap().OpenOrCreate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create map: %s\n", err)
		os.Exit(1)
	}
}

func dumpService(key []byte, value []byte) {
	keyBuf := bytes.NewBuffer(key)
	valueBuf := bytes.NewBuffer(value)

	if ipv4 {
		var svcKey LB4Key
		var svcVal LB4Service

		if err := binary.Read(keyBuf, binary.LittleEndian, &svcKey); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to convert data: %s\n", err)
			os.Exit(1)
		}

		if err := binary.Read(valueBuf, binary.LittleEndian, &svcVal); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to convert data: %s\n", err)
			os.Exit(1)
		}

		fmt.Printf("%v:%d %d => ", svcKey.Address, common.Swab16(svcKey.Port), svcKey.Slave)
		if svcKey.Slave == 0 {
			fmt.Printf("%d\n", svcVal.Count)
		} else {
			fmt.Printf("%v %d %d\n", svcVal.Address, common.Swab16(svcVal.Port), svcVal.RevNAT)
		}
	} else {
		var svcKey LB6Key
		var svcVal LB6Service

		if err := binary.Read(keyBuf, binary.LittleEndian, &svcKey); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to convert data: %s\n", err)
			os.Exit(1)
		}

		if err := binary.Read(valueBuf, binary.LittleEndian, &svcVal); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to convert data: %s\n", err)
			os.Exit(1)
		}

		fmt.Printf("%v:%d %d => ", svcKey.Address, common.Swab16(svcKey.Port), svcKey.Slave)
		if svcKey.Slave == 0 {
			fmt.Printf("%d\n", svcVal.Count)
		} else {
			fmt.Printf("%v %d\n", svcVal.Address, common.Swab16(svcVal.Port))
		}
	}
}

func lbDumpServices(ctx *cli.Context) {
	err := servicesMap().Dump(dumpService)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to dump map: %s\n", err)
		os.Exit(1)
	}
}

func dumpReverseNAT(key []byte, value []byte) {
	var revNATKey uint16

	keyBuf := bytes.NewBuffer(key)
	valueBuf := bytes.NewBuffer(value)

	if err := binary.Read(keyBuf, binary.LittleEndian, &revNATKey); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to convert data: %s\n", err)
		os.Exit(1)
	}
	revNATKey = common.Swab16(revNATKey)

	if ipv4 {
		var revNAT LB4ReverseNAT

		if err := binary.Read(valueBuf, binary.LittleEndian, &revNAT); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to convert data: %s\n", err)
			os.Exit(1)
		}

		fmt.Printf("%d => %v:%d\n", revNATKey, revNAT.Address, common.Swab16(revNAT.Port))
	} else {
		var revNAT LB6ReverseNAT

		if err := binary.Read(valueBuf, binary.LittleEndian, &revNAT); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to convert data: %s\n", err)
			os.Exit(1)
		}

		fmt.Printf("%d => %v:%d\n", revNATKey, revNAT.Address, common.Swab16(revNAT.Port))
	}
}

func lbDumpReverseNAT(ctx *cli.Context) {
	err := revNATMap().Dump(dumpReverseNAT)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to dump map: %s\n", err)
		os.Exit(1)
	}
}

func parseLB4Key(ctx *cli.Context, firstArg int) *LB4Key {
	if len(ctx.Args()) < (firstArg + 2) {
		printUsageAndExit(ctx)
	}

	key := LB4Key{}
	iv4, err := addressing.NewCiliumIPv4(ctx.Args().Get(firstArg))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid IPv4 address: %s\n", err)
		os.Exit(1)
	}
	copy(key.Address[:], iv4)

	key.Port = common.Swab16(parseUint16(ctx, firstArg+1))
	key.Slave = parseUint16(ctx, firstArg+2)

	return &key
}

func parseLB6Key(ctx *cli.Context, firstArg int) *LB6Key {
	if len(ctx.Args()) < (firstArg + 2) {
		printUsageAndExit(ctx)
	}

	key := LB6Key{}
	iv6, err := addressing.NewCiliumIPv6(ctx.Args().Get(firstArg))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid IPv6 address: %s\n", err)
		os.Exit(1)
	}
	copy(key.Address[:], iv6)

	key.Port = common.Swab16(parseUint16(ctx, firstArg+1))
	key.Slave = parseUint16(ctx, firstArg+2)

	return &key
}

func parseServiceKey(ctx *cli.Context, firstArg int) (bpf.MapObj, int) {
	if ipv4 {
		return parseLB4Key(ctx, firstArg), 3
	} else {
		return parseLB6Key(ctx, firstArg), 3
	}
}

func parseLB4Service(ctx *cli.Context, firstArg int) *LB4Service {
	if len(ctx.Args()) < (firstArg + 3) {
		printUsageAndExit(ctx)
	}

	svc := LB4Service{}
	svc.Count = parseUint16(ctx, firstArg)
	svc.RevNAT = common.Swab16(parseUint16(ctx, firstArg+1))
	svc.Port = common.Swab16(parseUint16(ctx, firstArg+3))

	target, err := addressing.NewCiliumIPv4(ctx.Args().Get(firstArg + 2))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid IPv4 address: %s\n", err)
		os.Exit(1)
	}
	copy(svc.Address[:], target)

	return &svc
}

func parseLB6Service(ctx *cli.Context, firstArg int) *LB6Service {
	if len(ctx.Args()) < (firstArg + 3) {
		printUsageAndExit(ctx)
	}

	svc := LB6Service{}
	svc.Count = parseUint16(ctx, firstArg)
	revNAT := parseUint16(ctx, firstArg+1)
	svc.Port = common.Swab16(parseUint16(ctx, firstArg+3))

	target, err := addressing.NewCiliumIPv6(ctx.Args().Get(firstArg + 2))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid IPv6 address: %s\n", err)
		os.Exit(1)
	}

	if revNAT != 0 {
		if target.State() != 0 {
			fmt.Fprintf(os.Stderr, "Error: Address has non-zero state bits.")
			os.Exit(1)
		}

		target.SetState(revNAT)
	}

	copy(svc.Address[:], target)

	return &svc
}

func parseService(ctx *cli.Context, firstArg int) unsafe.Pointer {
	if ipv4 {
		return unsafe.Pointer(parseLB4Service(ctx, firstArg))
	} else {
		return unsafe.Pointer(parseLB6Service(ctx, firstArg))
	}
}

func parseLB6ReverseNAT(ctx *cli.Context, firstArg int) *LB6ReverseNAT {
	revNAT := LB6ReverseNAT{}

	iv6, err := addressing.NewCiliumIPv6(ctx.Args().Get(firstArg))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid IPv6 address: %s\n", err)
		os.Exit(1)
	}
	copy(revNAT.Address[:], iv6)
	revNAT.Port = common.Swab16(parseUint16(ctx, 2))

	return &revNAT
}

func parseLB4ReverseNAT(ctx *cli.Context, firstArg int) *LB4ReverseNAT {
	revNAT := LB4ReverseNAT{}

	ip, err := addressing.NewCiliumIPv4(ctx.Args().Get(firstArg))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid IPv4 address: %s\n", err)
		os.Exit(1)
	}
	copy(revNAT.Address[:], ip)
	revNAT.Port = common.Swab16(parseUint16(ctx, 2))

	return &revNAT
}

func parseReverseNAT(ctx *cli.Context, firstArg int) unsafe.Pointer {
	if ipv4 {
		return unsafe.Pointer(parseLB4ReverseNAT(ctx, firstArg))
	} else {
		return unsafe.Pointer(parseLB6ReverseNAT(ctx, firstArg))
	}
}

func lbLookupService(ctx *cli.Context) {
	if ipv4 {
		key := parseLB4Key(ctx, 0)
		svc := &LB4Service{}
		err := servicesMap().Lookup(key, unsafe.Pointer(svc))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
		fmt.Printf("%v = %v\n", key, svc)
	} else {
		key := parseLB6Key(ctx, 0)
		svc := &LB6Service{}
		err := servicesMap().Lookup(key, unsafe.Pointer(svc))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
		fmt.Printf("%v = %v\n", key, svc)
	}
}

func lbLookupReverseNAT(ctx *cli.Context) {
	if len(ctx.Args()) < 1 {
		printUsageAndExit(ctx)
	}

	key := parseUint16(ctx, 0)
	revNATKey := NewRevNatKey(uint16(key))

	if ipv4 {
		revNAT := &LB4ReverseNAT{}
		err := revNATMap().Lookup(&revNATKey, unsafe.Pointer(revNAT))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}

		fmt.Printf("port %d = %v\n", key, revNAT)
	} else {
		revNAT := &LB6ReverseNAT{}
		err := revNATMap().Lookup(&revNATKey, unsafe.Pointer(revNAT))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}

		fmt.Printf("port %d = %v\n", key, revNAT)
	}
}

func lbUpdateService(ctx *cli.Context) {
	keyPtr, args := parseServiceKey(ctx, 0)
	svcPtr := parseService(ctx, args)

	if err := servicesMap().Update(keyPtr, svcPtr); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func lbUpdateReverseNAT(ctx *cli.Context) {
	if len(ctx.Args()) < 3 {
		printUsageAndExit(ctx)
	}

	u16key := NewRevNatKey(parseUint16(ctx, 0))
	revNATPtr := parseReverseNAT(ctx, 1)

	if err := revNATMap().Update(&u16key, revNATPtr); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func lbDeleteService(ctx *cli.Context) {
	if len(ctx.Args()) != 2 {
		printUsageAndExit(ctx)
	}

	ptr, _ := parseServiceKey(ctx, 0)
	if err := servicesMap().Delete(ptr); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}
}

func lbDeleteReverseNAT(ctx *cli.Context) {
	if len(ctx.Args()) != 1 {
		printUsageAndExit(ctx)
	}

	u16key := NewRevNatKey(parseUint16(ctx, 0))
	if err := revNATMap().Delete(&u16key); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}

}
