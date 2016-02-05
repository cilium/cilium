package main

/*
#include <linux/bpf.h>
#include <sys/resource.h>
*/
import "C"

import (
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	common "github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/bpf"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/codegangsta/cli"
)

const (
	errInvalidArgument = -1
	errIOFailure       = -2

	maxKeys    = 0xffff
	portmapMax = 16
)

type mac C.__u64

func (m mac) String() string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		uint64((m & 0x0000000000FF)),
		uint64((m&0x00000000FF00)>>8),
		uint64((m&0x000000FF0000)>>16),
		uint64((m&0x0000FF000000)>>24),
		uint64((m&0x00FF00000000)>>32),
		uint64((m&0xFF0000000000)>>40),
	)
}

func ParseMAC(s string) (mac, error) {
	ha, err := net.ParseMAC(s)
	if err != nil {
		return 0, err
	}
	if len(ha) != 6 {
		return 0, fmt.Errorf("invalid MAC address %s", s)
	}
	return mac(mac(ha[5])<<40 | mac(ha[4])<<32 | mac(ha[3])<<24 | mac(ha[2])<<16 | mac(ha[1])<<8 | mac(ha[0])), nil
}

type portmap struct {
	from uint16
	to   uint16
}

func (pm portmap) String() string {
	return fmt.Sprintf("%d:%d", common.Swab16(pm.from), common.Swab16(pm.to))
}

type lxcInfo struct {
	ifindex int
	mac     mac
	v6addr  v6addr
	portmap [portmapMax]portmap
}

func (lxc lxcInfo) String() string {
	var portmaps []string
	for _, port := range lxc.portmap {
		if pStr := port.String(); pStr != "0:0" {
			portmaps = append(portmaps, pStr)
		}
	}
	if len(portmaps) == 0 {
		portmaps = append(portmaps, "(empty)")
	}
	return fmt.Sprintf("ifindex=%d mac=%s ip=%s portmaps=%s",
		lxc.ifindex,
		lxc.mac,
		lxc.v6addr,
		strings.Join(portmaps, " "),
	)
}

type v6addr struct {
	addr [16]byte
}

func (v6 v6addr) String() string {
	return net.IP(v6.addr[:]).String()
}

type v6addrblock struct {
	p1 uint32
	p2 uint32
	p3 uint32
	p4 uint32
}

func printArgsUsage(ctx *cli.Context) {
	fmt.Fprintf(os.Stderr, "Usage: %s %s %s\n", ctx.App.Name, ctx.Command.Name,
		ctx.Command.ArgsUsage)
}

func main() {
	app := cli.NewApp()
	app.Name = "map-ctrl"
	app.Usage = "eBPF Control MAP"
	app.Version = "0.0.1"
	app.Commands = []cli.Command{
		{
			Name:      "create",
			Aliases:   []string{"c"},
			Usage:     "creates map on the given <map file>",
			ArgsUsage: "<map file>",
			Action:    MainBPFCreateMap,
		},
		{
			Name:      "dump",
			Aliases:   []string{"d"},
			Usage:     "dumps map present on the given <map file>",
			ArgsUsage: "<map file>",
			Action:    MainBPFDumpMap,
		},
		{
			Name:      "get",
			Aliases:   []string{"g"},
			Usage:     "gets key's value of the given <map file>",
			ArgsUsage: "<map file> <key>",
			Action:    MainBPFLookupKey,
		},
		{
			Name:      "update",
			Aliases:   []string{"u"},
			Usage:     "updates key's value of the given <map file>",
			ArgsUsage: "<map file> <key> <ifindex> <mac> <ipv6> [port_from:port_to [port_from:port_to]...]",
			Action:    MainBPFUpdateKey,
		},
		{
			Name:      "delete",
			Aliases:   []string{"D"},
			Usage:     "deletes key's value of the given <map file>",
			ArgsUsage: "<map file> <key>",
			Action:    MainBPFDeleteKey,
		},
	}

	rl := syscall.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	}

	err := syscall.Setrlimit(C.RLIMIT_MEMLOCK, &rl)
	if err != nil {
		fmt.Printf("Failled setting rlimit %s\n", err)
	}

	app.Run(os.Args)
}

func MainBPFCreateMap(ctx *cli.Context) {
	if len(ctx.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "Incorrect number of arguments.\n")
		fmt.Fprintf(os.Stderr, "Usage: %s %s %s\n", ctx.App.Name, ctx.Command.Name,
			ctx.Command.ArgsUsage)
		os.Exit(errInvalidArgument)
		return
	}
	file := ctx.Args().First()
	fmt.Println("file", file)
	fd, err := bpf.CreateMap(
		C.BPF_MAP_TYPE_HASH,
		uint32(unsafe.Sizeof(uint16(0))),
		uint32(unsafe.Sizeof(lxcInfo{})),
		maxKeys,
	)

	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
		return
	}

	err = bpf.ObjPin(fd, file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
		return
	}
}

func MainBPFDumpMap(ctx *cli.Context) {
	if len(ctx.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "Incorrect number of arguments.\n")
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
		return
	}

	file := ctx.Args().Get(0)

	fd, err := bpf.ObjGet(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
		return
	}

	var key, nextKey uint16
	key = maxKeys
	for {
		var lxc lxcInfo
		err := bpf.GetNextKey(
			fd,
			unsafe.Pointer(&key),
			unsafe.Pointer(&nextKey),
		)

		if err != nil {
			break
		}

		err = bpf.LookupElement(
			fd,
			unsafe.Pointer(&nextKey),
			unsafe.Pointer(&lxc),
		)

		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(errIOFailure)
			return
		} else {
			fmt.Printf("%d: %s\n", nextKey, lxc)
		}

		key = nextKey
	}
}

func lookupLxc(file string, key uint16) (*lxcInfo, error) {
	lxc := new(lxcInfo)

	fd, err := bpf.ObjGet(file)
	if err != nil {
		return nil, err
	}

	u16key := key
	err = bpf.LookupElement(fd, unsafe.Pointer(&u16key), unsafe.Pointer(lxc))

	return lxc, err
}

func MainBPFLookupKey(ctx *cli.Context) {
	if len(ctx.Args()) != 2 {
		fmt.Fprintf(os.Stderr, "Incorrect number of arguments.\n")
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
		return
	}

	file := ctx.Args().Get(0)

	key, err := strconv.ParseUint(ctx.Args().Get(1), 10, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
		return
	}

	lxc, err := lookupLxc(file, uint16(key))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(errIOFailure)
		return
	}
	fmt.Printf("%d: %s\n", key, lxc)
}

func MainBPFUpdateKey(ctx *cli.Context) {
	if len(ctx.Args()) < 5 {
		fmt.Fprintf(os.Stderr, "Incorrect number of arguments.\n")
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
		return
	}

	file := ctx.Args().Get(0)
	key, err := strconv.ParseUint(ctx.Args().Get(1), 10, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
		return
	}
	ifidx, err := strconv.ParseInt(ctx.Args().Get(2), 10, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
		return
	}
	macAddr, err := ParseMAC(ctx.Args().Get(3))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
		return
	}
	iv6 := net.ParseIP(ctx.Args().Get(4))
	if len(iv6) != net.IPv6len {
		fmt.Fprintf(os.Stderr, "invalid IPv6\n")
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
		return
	}

	lxc := lxcInfo{
		ifindex: int(ifidx),
		mac:     macAddr,
	}
	copy(lxc.v6addr.addr[:], iv6)

	remainingArgs := ctx.Args()[5:]
	if len(remainingArgs) > portmapMax {
		fmt.Fprintf(os.Stderr, "port mappings %d: maximum port mapping is %d\n", len(remainingArgs), portmapMax)
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
		return
	}
	for i, port := range remainingArgs {
		portSplit := strings.Split(port, ":")
		if len(portSplit) != 2 {
			fmt.Fprintf(os.Stderr, "%s: invalid port mapping\n", port)
			printArgsUsage(ctx)
			os.Exit(errInvalidArgument)
			return
		}
		from, err := strconv.ParseInt(portSplit[0], 10, 16)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			printArgsUsage(ctx)
			os.Exit(errInvalidArgument)
			return
		}
		to, err := strconv.ParseInt(portSplit[1], 10, 16)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			printArgsUsage(ctx)
			os.Exit(errInvalidArgument)
			return
		}
		lxc.portmap[i] = portmap{
			from: common.Swab16(uint16(from)),
			to:   common.Swab16(uint16(to)),
		}
	}

	fd, err := bpf.ObjGet(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
		return
	}

	u16key := uint16(key)
	err = bpf.UpdateElement(fd, unsafe.Pointer(&u16key), unsafe.Pointer(&lxc), 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(errIOFailure)
		return
	}
}

func MainBPFDeleteKey(ctx *cli.Context) {
	if len(ctx.Args()) != 2 {
		fmt.Fprintf(os.Stderr, "Incorrect number of arguments.\n")
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
		return
	}

	file := ctx.Args().Get(0)
	key, err := strconv.ParseUint(ctx.Args().Get(1), 10, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
		return
	}

	obj, err := bpf.ObjGet(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsage(ctx)
		os.Exit(errIOFailure)
		return
	}

	u16key := uint16(key)
	err = bpf.DeleteElement(obj, unsafe.Pointer(&u16key))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(errIOFailure)
		return
	}
}
