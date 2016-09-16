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
package lb

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/cilium/cilium/bpf/lbmap"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/bpf"

	"github.com/codegangsta/cli"
)

var (
	ipv4 bool

	// CliCommand is the command that will be used in cilium-net main program.
	CliCommand cli.Command
)

func parseUint16(ctx *cli.Context, argn int) uint16 {
	tmp, err := strconv.ParseUint(ctx.Args().Get(argn), 0, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid argument: %s\n", err)
		printUsageAndExit(ctx)
	}

	return uint16(tmp)
}

func printUsageAndExit(ctx *cli.Context) {
	fmt.Fprintf(os.Stderr, "Usage: %s %s %s\n", ctx.App.Name, ctx.Command.Name,
		ctx.Command.ArgsUsage)
	os.Exit(2)
}

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
				Name:   "create-services-map",
				Usage:  "creates the services map",
				Action: cliCreateServices,
			},
			{
				Name:   "create-rev-nat-map",
				Usage:  "creates the reverse NAT map",
				Action: cliCreateRevNat,
			},
			{
				Name:   "dump-service",
				Usage:  "dumps map present on the given <map file>",
				Action: cliDumpServices,
			},
			{
				Name:   "dump-rev-nat",
				Usage:  "dumps map present on the given <map file>",
				Action: cliDumpRevNat,
			},
			{
				Name:      "get-service",
				Usage:     "Lookup LB service",
				ArgsUsage: "<ipv6 addr> <dport> <slave index>",
				Action:    cliLookupService,
			},
			{
				Name:      "get-rev-nat",
				Usage:     "gets key's value of the given <map file>",
				ArgsUsage: "<reverse NAT key>",
				Action:    cliLookupRevNat,
			},
			{
				Name:      "update-service",
				Usage:     "updates key's value of the given <map file>",
				ArgsUsage: "<address> <port> <slave> <count> <reverse nat key> <slave address> <port>",
				Action:    cliUpdateService,
			},
			{
				Name:      "update-rev-nat",
				Usage:     "update LB reverse NAT table",
				ArgsUsage: "<reverse NAT key> <address> <port>",
				Action:    cliUpdateRevNat,
			},
			{
				Name:      "delete-service",
				Action:    cliDeleteService,
				ArgsUsage: "<address> <port> <slave-index>",
			},
			{
				Name:      "delete-rev-nat",
				Action:    cliDeleteRevNat,
				ArgsUsage: "<reverse NAT key>",
			},
		},
	}
}

func cliCreateServices(ctx *cli.Context) {
	var err error
	if ipv4 {
		_, err = lbmap.Service4Map.OpenOrCreate()
	} else {
		_, err = lbmap.Service6Map.OpenOrCreate()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create map: %s\n", err)
		os.Exit(1)
	}
}

func cliCreateRevNat(ctx *cli.Context) {
	var err error
	if ipv4 {
		_, err = lbmap.RevNat4Map.OpenOrCreate()
	} else {
		_, err = lbmap.RevNat6Map.OpenOrCreate()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create map: %s\n", err)
		os.Exit(1)
	}
}

func dumpService4(key bpf.MapKey, value bpf.MapValue) {
	svcKey := key.(*lbmap.Service4Key)
	svcVal := value.(*lbmap.Service4Value)

	fmt.Printf("%v:%d %d => ", svcKey.Address, svcKey.Port, svcKey.Slave)
	if svcKey.Slave == 0 {
		fmt.Printf("%d\n", svcVal.Count)
	} else {
		fmt.Printf("%v %d %d\n", svcVal.Address, svcVal.Port, svcVal.RevNAT)
	}
}

func dumpService6(key bpf.MapKey, value bpf.MapValue) {
	svcKey := key.(*lbmap.Service6Key)
	svcVal := value.(*lbmap.Service6Value)

	fmt.Printf("%v:%d %d => ", svcKey.Address, svcKey.Port, svcKey.Slave)
	if svcKey.Slave == 0 {
		fmt.Printf("%d\n", svcVal.Count)
	} else {
		fmt.Printf("%v %d\n", svcVal.Address, svcVal.Port)
	}
}

func cliDumpServices(ctx *cli.Context) {
	var err error

	if ipv4 {
		err = lbmap.Service4Map.Dump(lbmap.Service4DumpParser, dumpService4)
	} else {
		err = lbmap.Service6Map.Dump(lbmap.Service6DumpParser, dumpService6)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to dump map: %s\n", err)
		os.Exit(1)
	}
}

func dumpRevNat4(key bpf.MapKey, value bpf.MapValue) {
	v := value.(*lbmap.RevNat4Value)
	fmt.Printf("%d => %v:%d\n", *key.(*lbmap.RevNat4Key), v.Address, v.Port)
}

func dumpRevNat6(key bpf.MapKey, value bpf.MapValue) {
	v := value.(*lbmap.RevNat6Value)
	fmt.Printf("%d => %v:%d\n", *key.(*lbmap.RevNat6Key), v.Address, v.Port)
}

func cliDumpRevNat(ctx *cli.Context) {
	var err error

	if ipv4 {
		err = lbmap.RevNat4Map.Dump(lbmap.RevNat4DumpParser, dumpRevNat4)
	} else {
		err = lbmap.RevNat6Map.Dump(lbmap.RevNat6DumpParser, dumpRevNat6)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to dump map: %s\n", err)
		os.Exit(1)
	}
}

func parseServiceKey(ctx *cli.Context, firstArg int) lbmap.ServiceKey {
	if len(ctx.Args()) < (firstArg + 2) {
		printUsageAndExit(ctx)
	}

	address := ctx.Args().Get(firstArg)
	ip := net.ParseIP(address)
	if ip == nil {
		fmt.Fprintf(os.Stderr, "Unable to parse address: %s\n", address)
		os.Exit(1)
	}

	if ipv4 {
		if ip.To4() == nil {
			fmt.Fprintf(os.Stderr, "Expecting an IPv4 address, got: %s\n", address)
			os.Exit(1)
		}

		return lbmap.NewService4Key(ip, parseUint16(ctx, firstArg+1), parseUint16(ctx, firstArg+2))
	} else {
		if ip.To4() != nil {
			fmt.Fprintf(os.Stderr, "Expecting an IPv6 address, got: %s\n", address)
			os.Exit(1)
		}

		return lbmap.NewService6Key(ip, parseUint16(ctx, firstArg+1), parseUint16(ctx, firstArg+2))
	}
}

func parseServiceValue(ctx *cli.Context, ipv6 bool, firstArg int) lbmap.ServiceValue {
	if len(ctx.Args()) < (firstArg + 3) {
		printUsageAndExit(ctx)
	}

	address := ctx.Args().Get(firstArg + 2)
	target := net.ParseIP(address)
	if target == nil {
		fmt.Fprintf(os.Stderr, "Unable to parse address: %s\n", address)
		os.Exit(1)
	}

	if ipv6 {
		iv6, err := addressing.NewCiliumIPv6(address)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Expecting an IPv6 address, got: %s\n", address)
			os.Exit(1)
		}

		revNat := parseUint16(ctx, firstArg+1)

		if revNat != 0 {
			if iv6.State() != 0 {
				fmt.Fprintf(os.Stderr, "Error: Address has non-zero state bits.\n")
				os.Exit(1)
			}

			iv6.SetState(revNat)
		}

		return lbmap.NewService6Value(parseUint16(ctx, firstArg), iv6.IP(),
			parseUint16(ctx, firstArg+3))
	} else {
		if target.To4() == nil {
			fmt.Fprintf(os.Stderr, "Expecting an IPv4 address, got: %s\n", address)
			os.Exit(1)
		}

		return lbmap.NewService4Value(parseUint16(ctx, firstArg), target,
			parseUint16(ctx, firstArg+3), parseUint16(ctx, firstArg+1))
	}
}

func parseRevNat(ctx *cli.Context, ipv6 bool, firstArg int) lbmap.RevNatValue {
	if len(ctx.Args()) < (firstArg + 2) {
		printUsageAndExit(ctx)
	}

	address := ctx.Args().Get(firstArg)
	ip := net.ParseIP(address)
	if ip == nil {
		fmt.Fprintf(os.Stderr, "Unable to parse address: %s\n", address)
		os.Exit(1)
	}

	if ipv6 {
		if ip.To4() != nil {
			fmt.Fprintf(os.Stderr, "Expecting an IPv6 address, got: %s\n", address)
			os.Exit(1)
		}

		return lbmap.NewRevNat6Value(ip, parseUint16(ctx, 2))
	} else {
		if ip.To4() == nil {
			fmt.Fprintf(os.Stderr, "Expecting an IPv4 address, got: %s\n", address)
			os.Exit(1)
		}

		return lbmap.NewRevNat4Value(ip, parseUint16(ctx, 2))
	}
}

func cliLookupService(ctx *cli.Context) {
	key := parseServiceKey(ctx, 0)

	err, svc := lbmap.LookupService(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	fmt.Printf("%v = %v\n", key, svc)
}

func cliLookupRevNat(ctx *cli.Context) {
	if len(ctx.Args()) < 1 {
		printUsageAndExit(ctx)
	}

	key := parseRevNatKey(ctx)
	val, err := lbmap.LookupRevNat(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	fmt.Printf("%v = %v\n", key, val)
}

func cliUpdateService(ctx *cli.Context) {
	key := parseServiceKey(ctx, 0)
	svc := parseServiceValue(ctx, key.IsIPv6(), 3)

	if err := lbmap.UpdateService(key, svc); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func cliUpdateRevNat(ctx *cli.Context) {
	if len(ctx.Args()) < 3 {
		printUsageAndExit(ctx)
	}

	key := parseRevNatKey(ctx)
	val := parseRevNat(ctx, key.IsIPv6(), 1)

	fmt.Printf("%v %v\n", key, val)

	if err := lbmap.UpdateRevNat(key, val); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func cliDeleteService(ctx *cli.Context) {
	key := parseServiceKey(ctx, 0)

	if err := lbmap.DeleteService(key); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}
}

func parseRevNatKey(ctx *cli.Context) lbmap.RevNatKey {
	if len(ctx.Args()) < 1 {
		printUsageAndExit(ctx)
	}

	if ipv4 {
		return lbmap.NewRevNat4Key(parseUint16(ctx, 0))
	} else {
		return lbmap.NewRevNat6Key(parseUint16(ctx, 0))
	}
}

func cliDeleteRevNat(ctx *cli.Context) {
	key := parseRevNatKey(ctx)
	if err := lbmap.DeleteRevNat(key); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}
}
