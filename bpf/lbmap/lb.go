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
	"path/filepath"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/noironetworks/cilium-net/common/bpf"
	"github.com/noironetworks/cilium-net/common/types"

	"github.com/codegangsta/cli"
)

const (
	errInvalidArgument = -1
	errIOFailure       = -2
)

const (
	MaxLxc = 8
)

// lbServices : LBKey => LBValue, file cilium_lb_services
// lbState    : state => LBValue, file cilium_lb_state
const (
	lbServices = 1
	lbState    = 2
)

type LBKey struct {
	vip   v6Addr
	dport uint16
	pad   uint16
}

type LBLXCPair struct {
	LxcID  uint16
	Port   uint16
	NodeID uint32
}

type LBValue struct {
	vip      v6Addr
	dport    uint16
	state    uint16
	lxcCount int32
	lxc      [MaxLxc]LBLXCPair
}

type LBMap struct {
	fd int
}

type v6Addr types.IPv6

func printErrorAndExit(ctx *cli.Context, err string, code int) {
	fmt.Fprintf(os.Stderr, "%s\n", err)
	fmt.Fprintf(os.Stderr, "Usage: %s %s %s\n", ctx.App.Name, ctx.Command.Name,
		ctx.Command.ArgsUsage)
	os.Exit(code)
	return
}

func printArgsUsageAndExit(ctx *cli.Context) {
	printErrorAndExit(ctx, "Incorrect number of arguments.", errInvalidArgument)
	return
}

func main() {
	app := cli.NewApp()
	app.Name = "lb"
	app.Usage = "eBPF Control MAP"
	app.Version = "0.0.1"
	app.Commands = []cli.Command{
		{
			Name:      "create",
			Aliases:   []string{"c"},
			Usage:     "creates map on the given <map file>",
			ArgsUsage: "<map file> <lbtype>",
			Action:    lbCreateMap,
		},
		{
			Name:      "dump",
			Aliases:   []string{"d"},
			Usage:     "dumps map present on the given <map file>",
			ArgsUsage: "<map file>",
			Action:    lbDumpMap,
		},
		{
			Name:      "get",
			Aliases:   []string{"g"},
			Usage:     "gets key's value of the given <map file>",
			ArgsUsage: "<map file> <maptype 1> <ipv6 addr> <dport> | <map file> <maptype 2> <state>",
			Action:    lbLookupKey,
		},
		{
			Name:      "update",
			Aliases:   []string{"u"},
			Usage:     "updates key's value of the given <map file>",
			ArgsUsage: "<map file> <maptype> <ipv6 addr> <dport> <state> <count> [<lxc-id> <lxc-port> <node-id> ...]",
			Action:    lbUpdateKey,
		},
		{
			Name:      "delete",
			Aliases:   []string{"D"},
			Usage:     "deletes key's value of the given <map file>",
			ArgsUsage: "<map file> <maptype 1> <ipv6 addr> <dport> | <map file> <maptype 2> <state>",
			Action:    lbDeleteKey,
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

func lbOpenMap(path string, lbtype uint) (*LBMap, error) {
	var fd int

	rl := syscall.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	}

	err := syscall.Setrlimit(C.RLIMIT_MEMLOCK, &rl)
	if err != nil {
		return nil, fmt.Errorf("Unable to increase rlimit: %s", err)
	}

	if _, err = os.Stat(path); os.IsNotExist(err) {
		mapDir := filepath.Dir(path)
		if _, err = os.Stat(mapDir); os.IsNotExist(err) {
			if err = os.MkdirAll(mapDir, 0755); err != nil {
				return nil, fmt.Errorf("Unable create map base directory: %s", err)
			}
		}

		if lbtype == lbServices {
			fd, err = bpf.CreateMap(
				C.BPF_MAP_TYPE_HASH,
				uint32(unsafe.Sizeof(LBKey{})),
				uint32(unsafe.Sizeof(LBValue{})),
				32,
			)
		} else if lbtype == lbState {
			fd, err = bpf.CreateMap(
				C.BPF_MAP_TYPE_HASH,
				uint32(unsafe.Sizeof(uint16(0))),
				uint32(unsafe.Sizeof(LBValue{})),
				32,
			)
		} else {
			return nil, fmt.Errorf("Incorrect lbtype %d.\n", lbtype)
		}

		if err != nil {
			return nil, err
		}

		err = bpf.ObjPin(fd, path)
		if err != nil {
			return nil, err
		}
	} else {
		fd, err = bpf.ObjGet(path)
		if err != nil {
			return nil, err
		}
	}

	m := new(LBMap)
	m.fd = fd

	return m, nil
}

func lbCreateMap(ctx *cli.Context) {
	if len(ctx.Args()) != 2 {
		printArgsUsageAndExit(ctx)
		return
	}
	file := ctx.Args().First()

	lbtype, err := strconv.ParseUint(ctx.Args().Get(1), 10, 8)
	if err != nil {
		printArgsUsageAndExit(ctx)
		return
	}
	_, err = lbOpenMap(file, uint(lbtype))
	if err != nil {
		printArgsUsageAndExit(ctx)
		return
	}
}

func lbDumpMap(ctx *cli.Context) {
	if len(ctx.Args()) != 1 {
		printArgsUsageAndExit(ctx)
		return
	}

	file := ctx.Args().Get(0)

	fd, err := bpf.ObjGet(file)
	if err != nil {
		printErrorAndExit(ctx, "Failed to open file", errInvalidArgument)
		return
	}

	var key, nextKey LBKey
	for {
		var lbval LBValue
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
			unsafe.Pointer(&lbval),
		)

		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(errIOFailure)
			return
		}
		fmt.Printf("%#x: %d %d\n", nextKey, lbval.lxcCount, lbval.state)

		key = nextKey
	}
}

func lookupLb1(file string, key *LBKey) (*LBValue, error) {
	lbval := new(LBValue)

	fd, err := bpf.ObjGet(file)
	if err != nil {
		return nil, err
	}

	err = bpf.LookupElement(fd, unsafe.Pointer(key), unsafe.Pointer(lbval))

	return lbval, err
}

func lookupLb2(file string, key uint16) (*LBValue, error) {
	lbval := new(LBValue)

	fd, err := bpf.ObjGet(file)
	if err != nil {
		return nil, err
	}

	u16key := key
	err = bpf.LookupElement(fd, unsafe.Pointer(&u16key), unsafe.Pointer(lbval))

	return lbval, err
}

func lbLookupKey(ctx *cli.Context) {
	if len(ctx.Args()) < 2 {
		printArgsUsageAndExit(ctx)
		return
	}

	file := ctx.Args().Get(0)

	lbtype, err := strconv.ParseUint(ctx.Args().Get(1), 10, 8)
	if err != nil {
		printArgsUsageAndExit(ctx)
		return
	}

	if lbtype == lbServices {
		key := LBKey{}
		iv6 := net.ParseIP(ctx.Args().Get(2))
		if len(iv6) != net.IPv6len {
			printErrorAndExit(ctx, "invalid IPv6", errInvalidArgument)
			return
		}
		copy(key.vip[:], iv6)

		tmp, err := strconv.ParseUint(ctx.Args().Get(3), 10, 16)
		key.dport = uint16(tmp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			printArgsUsageAndExit(ctx)
			return
		}

		lbval, err := lookupLb1(file, &key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			printArgsUsageAndExit(ctx)
			return
		}

		fmt.Printf("key.vip %v, key.dport %d\n", key.vip, key.dport)
		fmt.Printf("value.state %d\n", lbval.state)
	} else if lbtype == lbState {
		key, err := strconv.ParseUint(ctx.Args().Get(2), 10, 16)
		if err != nil {
			printArgsUsageAndExit(ctx)
			return
		}

		lbval, err := lookupLb2(file, uint16(key))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(errIOFailure)
			return
		}

		fmt.Printf("key.dport %d\n", uint16(key))
		fmt.Printf("value.state %d\n", lbval.state)
	} else {
		fmt.Fprintf(os.Stderr, "Incorrect lbtype %d.\n", lbtype)
		printArgsUsageAndExit(ctx)
		return
	}
}

func lbUpdateKey(ctx *cli.Context) {
	lbval := LBValue{}

	if len(ctx.Args()) < 5 {
		printArgsUsageAndExit(ctx)
		return
	}

	file := ctx.Args().Get(0)

	lbtype, err := strconv.ParseUint(ctx.Args().Get(1), 10, 8)
	if err != nil {
		printArgsUsageAndExit(ctx)
		return
	}

	iv6 := net.ParseIP(ctx.Args().Get(2))
	if len(iv6) != net.IPv6len {
		fmt.Fprintf(os.Stderr, "invalid IPv6\n")
		printErrorAndExit(ctx, "invalid IPv6\n", errInvalidArgument)
		return
	}
	copy(lbval.vip[:], iv6)

	tmp, err := strconv.ParseUint(ctx.Args().Get(3), 10, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsageAndExit(ctx)
		return
	}
	lbval.dport = uint16(tmp)

	tmp, err = strconv.ParseUint(ctx.Args().Get(4), 10, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsageAndExit(ctx)
		return
	}
	lbval.state = uint16(tmp)

	count, err := strconv.ParseUint(ctx.Args().Get(5), 10, 16)
	if err != nil || count >= MaxLxc {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsageAndExit(ctx)
		return
	}
	lbval.lxcCount = int32(count)

	arg := 6
	for i := 0; i < int(count); i++ {
		tmp, err = strconv.ParseUint(ctx.Args().Get(arg), 10, 16)
		if err != nil {
			printArgsUsageAndExit(ctx)
			return
		}
		lbval.lxc[i].LxcID = uint16(tmp)

		tmp, err = strconv.ParseUint(ctx.Args().Get(arg+1), 10, 16)
		if err != nil {
			printArgsUsageAndExit(ctx)
			return
		}
		lbval.lxc[i].Port = uint16(tmp)

		tmp1, err := strconv.ParseUint(ctx.Args().Get(arg+2), 10, 32)
		if err != nil {
			printArgsUsageAndExit(ctx)
			return
		}
		lbval.lxc[i].NodeID = uint32(tmp1)
		arg += 3
	}

	remainingArgs := ctx.Args()[arg:]
	if len(remainingArgs) != 0 {
		fmt.Fprintf(os.Stderr, "Extra args at end of len %d\n", len(remainingArgs))
		printArgsUsageAndExit(ctx)
		return
	}

	fd, err := bpf.ObjGet(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsageAndExit(ctx)
		return
	}

	if lbtype == lbServices {
		key := LBKey{}
		key.vip = lbval.vip
		key.dport = lbval.dport
		err = bpf.UpdateElement(fd, unsafe.Pointer(&key), unsafe.Pointer(&lbval), 0)
	} else if lbtype == lbState {
		key := lbval.state
		u16key := uint16(key)
		err = bpf.UpdateElement(fd, unsafe.Pointer(&u16key), unsafe.Pointer(&lbval), 0)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsageAndExit(ctx)
		return
	}
}

func lbDeleteKey(ctx *cli.Context) {
	if len(ctx.Args()) != 2 {
		printArgsUsageAndExit(ctx)
		return
	}

	file := ctx.Args().Get(0)

	lbtype, err := strconv.ParseUint(ctx.Args().Get(1), 10, 8)
	if err != nil {
		printArgsUsageAndExit(ctx)
		return
	}

	obj, err := bpf.ObjGet(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		printArgsUsageAndExit(ctx)
		return
	}

	if lbtype == lbServices {
		key := LBKey{}
		iv6 := net.ParseIP(ctx.Args().Get(2))
		if len(iv6) != net.IPv6len {
			printErrorAndExit(ctx, "invalid IPv6\n", errInvalidArgument)
			return
		}
		copy(key.vip[:], iv6)

		tmp, err := strconv.ParseUint(ctx.Args().Get(3), 10, 16)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			printArgsUsageAndExit(ctx)
			return
		}
		key.dport = uint16(tmp)

		err = bpf.DeleteElement(obj, unsafe.Pointer(&key))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			printArgsUsageAndExit(ctx)
			return
		}
	} else if lbtype == lbState {
		key, err := strconv.ParseUint(ctx.Args().Get(2), 10, 16)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			printArgsUsageAndExit(ctx)
			return
		}

		u16key := uint16(key)
		err = bpf.DeleteElement(obj, unsafe.Pointer(&u16key))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			printArgsUsageAndExit(ctx)
			return
		}
	}
}
