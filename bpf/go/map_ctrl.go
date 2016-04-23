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

	"github.com/noironetworks/cilium-net/bpf/lxcmap"
	common "github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/bpf"

	"github.com/codegangsta/cli"
)

const (
	errInvalidArgument = -1
	errIOFailure       = -2
)

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
			Action:    mainBPFCreateMap,
		},
		{
			Name:      "dump",
			Aliases:   []string{"d"},
			Usage:     "dumps map present on the given <map file>",
			ArgsUsage: "<map file>",
			Action:    mainBPFDumpMap,
		},
		{
			Name:      "get",
			Aliases:   []string{"g"},
			Usage:     "gets key's value of the given <map file>",
			ArgsUsage: "<map file> <key>",
			Action:    mainBPFLookupKey,
		},
		{
			Name:      "update",
			Aliases:   []string{"u"},
			Usage:     "updates key's value of the given <map file>",
			ArgsUsage: "<map file> <key> <ifindex> <mac> <ipv6> [port_from:port_to [port_from:port_to]...]",
			Action:    mainBPFUpdateKey,
		},
		{
			Name:      "delete",
			Aliases:   []string{"D"},
			Usage:     "deletes key's value of the given <map file>",
			ArgsUsage: "<map file> <key>",
			Action:    mainBPFDeleteKey,
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

func mainBPFCreateMap(ctx *cli.Context) {
	if len(ctx.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "Incorrect number of arguments.\n")
		fmt.Fprintf(os.Stderr, "Usage: %s %s %s\n", ctx.App.Name, ctx.Command.Name,
			ctx.Command.ArgsUsage)
		os.Exit(errInvalidArgument)
		return
	}
	file := ctx.Args().First()

	_, err := lxcmap.OpenMap(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
	}
}

func mainBPFDumpMap(ctx *cli.Context) {
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
	key = lxcmap.MaxKeys
	for {
		var lxc lxcmap.LXCInfo
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
		}
		fmt.Printf("%#x: %s\n", nextKey, lxc)

		key = nextKey
	}
}

func lookupLXC(file string, key uint16) (*lxcmap.LXCInfo, error) {
	lxc := new(lxcmap.LXCInfo)

	fd, err := bpf.ObjGet(file)
	if err != nil {
		return nil, err
	}

	u16key := key
	err = bpf.LookupElement(fd, unsafe.Pointer(&u16key), unsafe.Pointer(lxc))

	return lxc, err
}

func mainBPFLookupKey(ctx *cli.Context) {
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

	lxc, err := lookupLXC(file, uint16(key))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(errIOFailure)
		return
	}
	fmt.Printf("%d: %s\n", key, lxc)
}

func mainBPFUpdateKey(ctx *cli.Context) {
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
	macAddr, err := lxcmap.ParseMAC(ctx.Args().Get(3))
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

	lxc := lxcmap.LXCInfo{
		IfIndex: uint32(ifidx),
		MAC:     macAddr,
	}
	copy(lxc.V6Addr[:], iv6)

	remainingArgs := ctx.Args()[5:]
	if len(remainingArgs) > lxcmap.PortMapMax {
		fmt.Fprintf(os.Stderr, "port mappings %d: maximum port mapping is %d\n", len(remainingArgs), lxcmap.PortMapMax)
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
		lxc.PortMap[i] = lxcmap.PortMap{
			From: common.Swab16(uint16(from)),
			To:   common.Swab16(uint16(to)),
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

func mainBPFDeleteKey(ctx *cli.Context) {
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
