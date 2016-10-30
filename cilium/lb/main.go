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
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"

	"github.com/cilium/cilium/bpf/lbmap"
	"github.com/cilium/cilium/common/bpf"

	"github.com/codegangsta/cli"
)

var (
	ipv4   bool
	addRev bool

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
				ArgsUsage: "<address>:<port>",
				Action:    cliLookupService,
			},
			{
				Name:      "get-rev-nat",
				Usage:     "gets key's value of the given <map file>",
				ArgsUsage: "<reverse NAT key>",
				Action:    cliLookupRevNat,
			},
			{
				Name:  "update-service",
				Usage: "Update service entry",
				Flags: []cli.Flag{
					cli.BoolFlag{
						Destination: &addRev,
						Name:        "rev",
						Usage:       "Also add/update corresponding reverse NAT entry",
					},
					cli.StringFlag{
						Name:  "frontend",
						Usage: "Address of frontend (required)",
					},
					cli.StringSliceFlag{
						Name:  "backend",
						Usage: "Backend address and port",
					},
					cli.IntFlag{
						Name:  "id",
						Usage: "Identifier to be used for reverse mapping",
					},
				},
				Action: cliUpdateService,
			},
			{
				Name:  "update-rev-nat",
				Usage: "update LB reverse NAT table",
				Flags: []cli.Flag{
					cli.StringFlag{
						Name:  "address",
						Usage: "Address and port to translate back to",
					},
					cli.IntFlag{
						Name:  "id",
						Usage: "Identifier to be used for reverse mapping",
					},
				},
				Action: cliUpdateRevNat,
			},
			{
				Name:   "delete-service",
				Action: cliDeleteService,
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:  "all",
						Usage: "Delete all entries",
					},
				},
				ArgsUsage: "--all | <address>:<port>",
			},
			{
				Name:   "delete-rev-nat",
				Action: cliDeleteRevNat,
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:  "all",
						Usage: "Delete all entries",
					},
				},
				ArgsUsage: "--all | <reverse NAT key>",
			},
		},
	}
}

type ServiceDump struct {
	Keys     []int
	Backends map[int]lbmap.ServiceValue
}

var dumpTable map[string]*ServiceDump

func addToDumpTable(keyStr string, key lbmap.ServiceKey, value lbmap.ServiceValue) {
	var sd *ServiceDump

	sd, _ = dumpTable[keyStr]
	if sd == nil {
		sd = &ServiceDump{Backends: map[int]lbmap.ServiceValue{}}
		dumpTable[keyStr] = sd
	}

	if backend := key.GetBackend(); backend != 0 {
		sd.Backends[backend] = value
		sd.Keys = append(sd.Keys, backend)
	}
}

func dumpService4(key bpf.MapKey, value bpf.MapValue) {
	svcKey := key.(*lbmap.Service4Key)
	svcVal := value.(*lbmap.Service4Value)
	addToDumpTable(svcKey.String(), svcKey, svcVal)
}

func dumpService6(key bpf.MapKey, value bpf.MapValue) {
	svcKey := key.(*lbmap.Service6Key)
	svcVal := value.(*lbmap.Service6Value)
	addToDumpTable(svcKey.String(), svcKey, svcVal)
}

func cliDumpServices(ctx *cli.Context) {
	dumpTable = map[string]*ServiceDump{}

	if err := lbmap.Service4Map.Dump(lbmap.Service4DumpParser, dumpService4); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Unable to dump map: %s\n", err)
	}

	if err := lbmap.Service6Map.Dump(lbmap.Service6DumpParser, dumpService6); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Unable to dump map: %s\n", err)
	}

	var keys []string
	for k := range dumpTable {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k1 := range keys {
		fmt.Printf("%s =>\n", k1)
		sort.Ints(dumpTable[k1].Keys)
		for _, k2 := range dumpTable[k1].Keys {
			fmt.Printf("\t\t%d => %s\n", k2, dumpTable[k1].Backends[k2])
		}
	}
}

func dumpRevNat4(key bpf.MapKey, value bpf.MapValue) {
	k := key.(*lbmap.RevNat4Key)
	v := value.(*lbmap.RevNat4Value)
	fmt.Printf("  %d => %s\n", k.Key, v)
}

func dumpRevNat6(key bpf.MapKey, value bpf.MapValue) {
	k := key.(*lbmap.RevNat6Key)
	v := value.(*lbmap.RevNat6Value)
	fmt.Printf("  %d => %s\n", k.Key, v)
}

func cliDumpRevNat(ctx *cli.Context) {
	fmt.Printf("IPv6:\n")
	if err := lbmap.RevNat6Map.Dump(lbmap.RevNat6DumpParser, dumpRevNat6); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to dump map: %s\n", err)
	}

	fmt.Printf("IPv4:\n")
	if err := lbmap.RevNat4Map.Dump(lbmap.RevNat4DumpParser, dumpRevNat4); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to dump map: %s\n", err)
	}
}

func parseServiceKey(address string) lbmap.ServiceKey {
	frontend, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse frontend address: %s\n", err)
		os.Exit(1)
	}

	if frontend.IP.To4() != nil {
		return lbmap.NewService4Key(frontend.IP, uint16(frontend.Port), 0)
	} else {
		return lbmap.NewService6Key(frontend.IP, uint16(frontend.Port), 0)
	}
}

func cliLookupService(ctx *cli.Context) {
	key := parseServiceKey(ctx.Args().Get(0))

	svc, err := lbmap.LookupService(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s = %s\n", key, svc)
}

func cliLookupRevNat(ctx *cli.Context) {
	key := parseRevNatKey(ctx.Args().Get(0))
	val, err := lbmap.LookupRevNat(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	fmt.Printf("%v = %v\n", key, val)
}

func cliUpdateService(ctx *cli.Context) {
	key := parseServiceKey(ctx.String("frontend"))
	svc := key.NewValue().(lbmap.ServiceValue)
	backends := []*net.TCPAddr{}

	proto := "tcp4"
	if key.IsIPv6() {
		proto = "tcp6"
	}

	revNat := ctx.Int("id")

	backendList := ctx.StringSlice("backend")
	if len(backendList) == 0 {
		fmt.Printf("Reading backend list from stdin...\n")

		scanner := bufio.NewScanner(os.Stdin)

		for scanner.Scan() {
			backendList = append(backendList, scanner.Text())
		}
	}

	for k := range backendList {
		tcpAddr, err := net.ResolveTCPAddr(proto, backendList[k])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}

		if tcpAddr.IP.To4() != nil && key.IsIPv6() {
			fmt.Fprintf(os.Stderr, "Address mismatch between frontend and backend %s\n",
				backendList[k])
			os.Exit(1)
		}

		if key.GetPort() == 0 && tcpAddr.Port != 0 {
			fmt.Fprintf(os.Stderr, "L4 backend found (%v) with L3 frontend\n", tcpAddr)
			os.Exit(1)
		}

		backends = append(backends, tcpAddr)
	}

	idx := 1
	for k := range backends {
		key.SetBackend(idx)
		if err := svc.SetAddress(backends[k].IP); err != nil {
			// FIXME: Undo the damage that is already done
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}

		svc.SetPort(uint16(backends[k].Port))
		svc.SetRevNat(revNat)

		fmt.Printf("Adding %+v %+v\n", key, svc)

		if err := lbmap.UpdateService(key, svc); err != nil {
			// FIXME: Undo the damage that is already done
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}

		idx++
	}

	if addRev {
		revKey := svc.RevNatKey()
		revVal := key.RevNatValue()

		fmt.Printf("Adding %+v %+v\n", revKey, revVal)
		if err := lbmap.UpdateRevNat(revKey, revVal); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}

		fmt.Printf("Added reverse NAT entry\n")
	}

	// Create master service last to avoid hitting backends all of
	// them have been inserted into the map
	key.SetBackend(0)
	svc.SetCount(len(backends))
	svc.SetPort(uint16(0))
	svc.SetRevNat(0)

	fmt.Printf("Adding %+v %+v\n", key, svc)
	if err := lbmap.UpdateService(key, svc); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Added %d backends\n", idx-1)
}

func cliUpdateRevNat(ctx *cli.Context) {
	var key lbmap.RevNatKey
	var val lbmap.RevNatValue

	tcpAddr, err := net.ResolveTCPAddr("tcp", ctx.String("address"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	k := uint16(ctx.Int("id"))

	if tcpAddr.IP.To4() != nil {
		key = lbmap.NewRevNat4Key(k)
		val = lbmap.NewRevNat4Value(tcpAddr.IP, uint16(tcpAddr.Port))
	} else {
		key = lbmap.NewRevNat6Key(k)
		val = lbmap.NewRevNat6Value(tcpAddr.IP, uint16(tcpAddr.Port))
	}

	if err := lbmap.UpdateRevNat(key, val); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func cliDeleteService(ctx *cli.Context) {
	var err error

	if ctx.Bool("all") {
		if err := lbmap.Service6Map.DeleteAll(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %s\n", err)
		}

		if err := lbmap.Service4Map.DeleteAll(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %s\n", err)
		}
	} else {
		key := parseServiceKey(ctx.Args().Get(0))
		val, err := lbmap.LookupService(key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}

		svc := val.(lbmap.ServiceValue)
		fmt.Printf("Deleting %d backends...\n", svc.GetCount())
		for i := 1; i <= svc.GetCount(); i++ {
			key.SetBackend(i)
			if err := lbmap.DeleteService(key); err != nil {
				fmt.Fprintf(os.Stderr, "%s", err)
				os.Exit(1)
			}
		}

		key.SetBackend(0)
		fmt.Printf("Deleting master entry %v\n", key)
		err = lbmap.DeleteService(key)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}
}

func parseRevNatKey(key string) lbmap.RevNatKey {
	k, err := strconv.ParseUint(key, 0, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}

	if ipv4 {
		return lbmap.NewRevNat4Key(uint16(k))
	} else {
		return lbmap.NewRevNat6Key(uint16(k))
	}
}

func cliDeleteRevNat(ctx *cli.Context) {
	if ctx.Bool("all") {
		if err := lbmap.RevNat6Map.DeleteAll(); err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			os.Exit(1)
		}

		if err := lbmap.RevNat4Map.DeleteAll(); err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			os.Exit(1)
		}
	} else {
		if err := lbmap.DeleteRevNat(parseRevNatKey(ctx.Args().Get(0))); err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			os.Exit(1)
		}
	}
}
