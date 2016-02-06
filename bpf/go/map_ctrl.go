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

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/codegangsta/cli"
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

	_, err := lxcmap.CreateMap(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsage(ctx)
		os.Exit(errInvalidArgument)
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
	key = lxcmap.MAX_KEYS
	for {
		var lxc lxcmap.LxcInfo
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

func lookupLxc(file string, key uint16) (*lxcmap.LxcInfo, error) {
	lxc := new(lxcmap.LxcInfo)

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

	lxc := lxcmap.LxcInfo{
		Ifindex: int(ifidx),
		Mac:     macAddr,
	}
	copy(lxc.V6addr.Addr[:], iv6)

	remainingArgs := ctx.Args()[5:]
	if len(remainingArgs) > lxcmap.PORTMAP_MAX {
		fmt.Fprintf(os.Stderr, "port mappings %d: maximum port mapping is %d\n", len(remainingArgs), lxcmap.PORTMAP_MAX)
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
		lxc.Portmap[i] = lxcmap.Portmap{
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
