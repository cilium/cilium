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

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/backend"
	cnc "github.com/cilium/cilium/common/client"
	"github.com/cilium/cilium/common/types"

	l "github.com/op/go-logging"
	"github.com/urfave/cli"
)

var (
	addRev   bool
	noDaemon bool

	client backend.LBBackend
	log    = l.MustGetLogger("cilium-cli")

	// CliCommand is the command that will be used in cilium-net main program.
	CliCommand cli.Command
)

func init() {
	CliCommand = cli.Command{
		Name:  "lb",
		Usage: "Configure daemon's load balancer",
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:        "no-daemon",
				Usage:       "Don't connect to daemon and modify the bpf maps directly. WARNING: Might cause data corruption if daemon is running at the same time",
				Destination: &noDaemon,
			},
		},
		Subcommands: []cli.Command{
			{
				Name:   "dump-service",
				Usage:  "Dumps the Service map present on the daemon",
				Action: cliDumpServices,
				Before: initEnv,
			},
			{
				Name:   "dump-rev-nat",
				Usage:  "Dumps the RevNAT map present on the daemon",
				Action: cliDumpRevNat,
				Before: initEnv,
			},
			{
				Name:      "get-service",
				Usage:     "Lookup LB Service from the daemon",
				ArgsUsage: "(<IPv4Address>:<port> | [<IPv6Address>]:<port>)",
				Action:    cliLookupService,
				Before:    initEnv,
			},
			{
				Name:      "get-rev-nat",
				Usage:     "Lookup Reverse NAT's value from the daemon",
				ArgsUsage: "<reverse NAT key>",
				Action:    cliLookupRevNat,
				Before:    initEnv,
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
				Before: initEnv,
			},
			{
				Name:  "update-rev-nat",
				Usage: "Update LB Reverse NAT table",
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
				Before: initEnv,
			},
			{
				Name:   "delete-service",
				Usage:  "Deletes the service and respective backends",
				Action: cliDeleteService,
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:  "all",
						Usage: "Delete all entries",
					},
				},
				ArgsUsage: "--all | (<IPv4Address>:<port> | [<IPv6Address>]:<port>)",
				Before:    initEnv,
			},
			{
				Name:   "delete-rev-nat",
				Usage:  "Deletes the Reverse NAT from the daemon",
				Action: cliDeleteRevNat,
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:  "all",
						Usage: "Delete all entries",
					},
				},
				ArgsUsage: "--all | <reverse NAT key>",
				Before:    initEnv,
			},
			{
				Name:   "sync-lb-maps",
				Usage:  "Syncs bpf LB maps with the running daemon",
				Action: cliSyncLBMaps,
				Before: initEnv,
			},
		},
	}
}

func initEnv(ctx *cli.Context) error {
	if ctx.GlobalBool("debug") {
		common.SetupLOG(log, "DEBUG")
	} else {
		common.SetupLOG(log, "INFO")
	}

	if noDaemon {
		client = NewLBClient()
	} else {
		var (
			c   *cnc.Client
			err error
		)
		if host := ctx.GlobalString("host"); host == "" {
			c, err = cnc.NewDefaultClient()
		} else {
			c, err = cnc.NewClient(host, nil)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while creating cilium-client: %s\n", err)
			return fmt.Errorf("Error while creating cilium-client: %s", err)
		}
		client = c
	}

	return nil
}

func cliDumpServices(ctx *cli.Context) {
	dump, err := client.SVCDump()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Unable to dump map: %s\n", err)
	}

	svcs := map[string][]string{}
	for _, v := range dump {
		besWithID := []string{}
		for i, be := range v.BES {
			str := fmt.Sprintf("%d => %s (%d)", i+1, be.String(), v.FE.ID)
			besWithID = append(besWithID, str)
		}
		svcs[v.FE.L3n4Addr.String()] = besWithID
	}

	var svcsKeys []string
	for k := range svcs {
		svcsKeys = append(svcsKeys, k)
	}
	sort.Strings(svcsKeys)

	for _, svcKey := range svcsKeys {
		fmt.Printf("%s =>\n", svcKey)
		for _, be := range svcs[svcKey] {
			fmt.Printf("\t\t%s\n", be)
		}
	}
}

func cliDumpRevNat(ctx *cli.Context) {
	dump, err := client.RevNATDump()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Unable to dump map: %s\n", err)
	}

	revNatFormat := map[int]string{}
	revNatFormatKeysV4 := []int{}
	revNatFormatKeysV6 := []int{}
	for _, revNat := range dump {
		revNatFormat[int(revNat.ID)] = revNat.String()
		if revNat.IsIPv6() {
			revNatFormatKeysV6 = append(revNatFormatKeysV6, int(revNat.ID))
		} else {
			revNatFormatKeysV4 = append(revNatFormatKeysV4, int(revNat.ID))
		}
	}
	sort.Ints(revNatFormatKeysV6)
	sort.Ints(revNatFormatKeysV4)

	if len(revNatFormatKeysV6) != 0 {
		fmt.Printf("IPv6:\n")
		for _, revNATID := range revNatFormatKeysV6 {
			fmt.Printf("%d => %s\n", revNATID, revNatFormat[revNATID])
		}
	}

	if len(revNatFormatKeysV4) != 0 {
		fmt.Printf("IPv4:\n")
		for _, revNATID := range revNatFormatKeysV4 {
			fmt.Printf("%d => %s\n", revNATID, revNatFormat[revNATID])
		}
	}
}

func parseServiceKey(address string) *types.L3n4Addr {
	frontend, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse frontend address: %s\n", err)
		os.Exit(1)
	}

	l3n4Addr, err := types.NewL3n4Addr(types.TCP, frontend.IP, uint16(frontend.Port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse frontend address: %s\n", err)
		os.Exit(1)
	}
	return l3n4Addr
}

func cliLookupService(ctx *cli.Context) {
	if len(ctx.Args()) == 0 {
		cli.ShowCommandHelp(ctx, "get-service")
		os.Exit(1)
	}
	key := parseServiceKey(ctx.Args().Get(0))

	lbSVC, err := client.SVCGet(*key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to receive service from daemon: %s\n", err)
		os.Exit(1)
	}
	if lbSVC == nil {
		fmt.Fprintf(os.Stderr, "Entry not found \n")
		os.Exit(1)
	}

	besSlice := []string{}
	for _, revNat := range lbSVC.BES {
		besSlice = append(besSlice, revNat.String())
	}

	fmt.Printf("%s =>\n", key.String())
	for i, svcBackend := range besSlice {
		fmt.Printf("\t\t%d => %s (%d)\n", i+1, svcBackend, lbSVC.FE.ID)
	}
}

func parseRevNatKey(key string) types.ServiceID {
	k, err := strconv.ParseUint(key, 0, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}
	return types.ServiceID(k)
}

func cliLookupRevNat(ctx *cli.Context) {
	if len(ctx.Args()) == 0 {
		cli.ShowCommandHelp(ctx, "get-rev-nat")
		os.Exit(1)
	}
	key := parseRevNatKey(ctx.Args().Get(0))

	val, err := client.RevNATGet(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	if val == nil {
		fmt.Fprintf(os.Stderr, "Entry not found \n")
		os.Exit(1)
	}

	fmt.Printf("%d => %v\n", key, val)
}

func cliUpdateService(ctx *cli.Context) {
	feL3n4Addr := parseServiceKey(ctx.String("frontend"))
	backends := []types.L3n4Addr{}
	fe := types.L3n4AddrID{
		ID:       types.ServiceID(ctx.Int("id")),
		L3n4Addr: *feL3n4Addr,
	}

	backendList := ctx.StringSlice("backend")
	if len(backendList) == 0 {
		fmt.Printf("Reading backend list from stdin...\n")

		scanner := bufio.NewScanner(os.Stdin)

		for scanner.Scan() {
			backendList = append(backendList, scanner.Text())
		}
	}

	for _, backend := range backendList {
		beAddr, err := net.ResolveTCPAddr("tcp", backend)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}

		be, err := types.NewL3n4Addr(types.TCP, beAddr.IP, uint16(beAddr.Port))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to create a new L3n4Addr for backend %s: %s\n", backend, err)
			os.Exit(1)
		}

		if !be.IsIPv6() && fe.IsIPv6() {
			fmt.Fprintf(os.Stderr, "Address mismatch between frontend and backend %s\n",
				backend)
			os.Exit(1)
		}

		if fe.Port == 0 && beAddr.Port != 0 {
			fmt.Fprintf(os.Stderr, "L4 backend found (%v) with L3 frontend\n", beAddr)
			os.Exit(1)
		}

		backends = append(backends, *be)
	}

	if err := client.SVCAdd(fe, backends, addRev); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to add the service: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Added %d backends\n", len(backends))
}

func cliUpdateRevNat(ctx *cli.Context) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", ctx.String("address"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	val, err := types.NewL3n4Addr(types.TCP, tcpAddr.IP, uint16(tcpAddr.Port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create a new L3n4Addr: %s\n", err)
		os.Exit(1)
	}

	id := types.ServiceID(ctx.Int("id"))

	if err := client.RevNATAdd(id, *val); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func cliDeleteService(ctx *cli.Context) {
	var err error

	if ctx.Bool("all") {
		if err := client.SVCDeleteAll(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %s\n", err)
		}
	} else {
		if len(ctx.Args()) == 0 {
			cli.ShowCommandHelp(ctx, "delete-service")
			os.Exit(1)
		}
		fe := parseServiceKey(ctx.Args().Get(0))
		err = client.SVCDelete(*fe)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully deleted\n")
}

func cliDeleteRevNat(ctx *cli.Context) {
	if ctx.Bool("all") {
		if err := client.RevNATDeleteAll(); err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			os.Exit(1)
		}
	} else {
		if len(ctx.Args()) == 0 {
			cli.ShowCommandHelp(ctx, "delete-rev-nat")
			os.Exit(1)
		}

		id, err := strconv.ParseUint(ctx.Args().Get(0), 10, 16)
		if err != nil {
			cli.ShowCommandHelp(ctx, "delete-rev-nat")
			os.Exit(1)
		}

		if err := client.RevNATDelete(types.ServiceID(id)); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("Successfully deleted\n")
}

func cliSyncLBMaps(_ *cli.Context) {
	if err := client.SyncLBMap(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Maps successfully synced\n")
}
