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
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/types"

	"github.com/go-openapi/swag"
	"github.com/urfave/cli"
)

var (
	addRev bool
	bypass bool
	cliLB  cli.Command
)

func init() {
	cliLB = cli.Command{
		Name:  "service",
		Usage: "Configure services & loadbalancer",
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:        "bypass",
				Usage:       "Modify BPF maps directly. WARNING: Might cause data corruption if daemon is running at the same time",
				Destination: &bypass,
			},
		},
		Subcommands: []cli.Command{
			{
				Name:   "list",
				Usage:  "List all services",
				Action: cliDumpServices,
			},
			{
				Name:      "inspect",
				Usage:     "Inspect service configuration",
				ArgsUsage: "<ID>",
				Action:    cliLookupService,
			},
			{
				Name:  "update",
				Usage: "Update service configuration",
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
				Name:   "delete",
				Usage:  "Delete service",
				Action: cliDeleteService,
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:  "all",
						Usage: "Delete all entries",
					},
				},
				ArgsUsage: "--all | (<IPv4Address>:<port> | [<IPv6Address>]:<port>)",
			},
		},
	}
}

func cliDumpServices(ctx *cli.Context) {
	if bypass {
		Fatalf("Bypass not supported for this operation")
	}

	list, err := client.GetServices()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Unable to dump map: %s\n", err)
	}

	svcs := map[string][]string{}
	for _, svc := range list {
		besWithID := []string{}
		for i, be := range svc.BackendAddresses {
			beA, err := types.NewL3n4AddrFromBackendModel(be)
			if err != nil {
				fmt.Printf("error parsing backend %+v", be)
				continue
			}
			str := fmt.Sprintf("%d => %s (%d)", i+1, beA.String(), svc.ID)
			besWithID = append(besWithID, str)
		}

		feA, err := types.NewL3n4AddrFromModel(svc.FrontendAddress)
		if err != nil {
			fmt.Printf("error parsing frontend %+v", svc.FrontendAddress)
			continue
		}
		svcs[feA.String()] = besWithID
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

func parseFrontendAddress(address string) (*models.FrontendAddress, net.IP) {
	frontend, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		Fatalf("Unable to parse frontend address: %s\n", err)
	}

	// FIXME support more than TCP
	return &models.FrontendAddress{
		IP:       swag.String(frontend.IP.String()),
		Port:     uint16(frontend.Port),
		Protocol: models.FrontendAddressProtocolTCP,
	}, frontend.IP
}

func cliLookupService(ctx *cli.Context) {
	if bypass {
		Fatalf("Bypass not supported for this operation")
	}

	if len(ctx.Args()) == 0 {
		cli.ShowCommandHelp(ctx, "inspect")
		os.Exit(1)
	}

	svcIDstr := ctx.Args().Get(0)
	id, err := strconv.ParseInt(svcIDstr, 0, 64)
	if err != nil {
		Fatalf("Unable to parse service ID: %s", svcIDstr)
	}

	svc, err := client.GetServiceID(id)
	if err != nil {
		Fatalf("Unable to receive service from daemon: %s\n", err)
	}

	slice := []string{}
	for _, be := range svc.BackendAddresses {
		if bea, err := types.NewL3n4AddrFromBackendModel(be); err != nil {
			slice = append(slice, fmt.Sprintf("invalid backend: %+v", be))
		} else {
			slice = append(slice, bea.String())
		}
	}

	if fea, err := types.NewL3n4AddrFromModel(svc.FrontendAddress); err != nil {
		fmt.Printf("invalid frontend model: %s", err)
	} else {
		fmt.Printf("%s =>\n", fea.String())
	}

	for i, be := range slice {
		fmt.Printf("\t\t%d => %s (%d)\n", i+1, be, svc.ID)
	}
}

func putServiceID(id int64, svc *models.Service) (bool, error) {
	if bypass {
		return false, bypassPutService(id, svc)
	} else {
		return client.PutServiceID(id, svc)
	}
}

func cliUpdateService(ctx *cli.Context) {
	id := int64(ctx.Int("id"))
	fa, faIP := parseFrontendAddress(ctx.String("frontend"))

	svc := &models.Service{
		ID:               id,
		FrontendAddress:  fa,
		BackendAddresses: []*models.BackendAddress{},
		Flags: &models.ServiceFlags{
			DirectServerReturn: addRev,
		},
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
			Fatalf("%s\n", err)
		}

		be, err := types.NewL3n4Addr(types.TCP, beAddr.IP, uint16(beAddr.Port))
		if err != nil {
			Fatalf("Unable to create a new L3n4Addr for backend %s: %s\n", backend, err)
		}

		if be.IsIPv6() && faIP.To4() != nil {
			Fatalf("Address mismatch between frontend and backend %s\n", backend)
		}

		if fa.Port == 0 && beAddr.Port != 0 {
			Fatalf("L4 backend found (%v) with L3 frontend\n", beAddr)
		}

		ba := be.GetBackendModel()
		svc.BackendAddresses = append(svc.BackendAddresses, ba)
	}

	if created, err := putServiceID(id, svc); err != nil {
		Fatalf("Unable to add the service: %s\n", err)
	} else if created {
		fmt.Printf("Added service with %d backends\n", len(svc.BackendAddresses))
	} else {
		fmt.Printf("Updated service with %d backends\n", len(svc.BackendAddresses))
	}
}

func cliDeleteService(ctx *cli.Context) {
	if bypass {
		Fatalf("Bypass not supported for this operation")
	}

	if ctx.Bool("all") {
		list, err := client.GetServices()
		if err != nil {
			Fatalf("Unable to get list of services: %s", err)
		}

		for _, svc := range list {
			if err := client.DeleteServiceID(svc.ID); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Unable to delete service %v: %s",
					svc, err)
			}
		}

		return
	}

	if len(ctx.Args()) == 0 {
		cli.ShowCommandHelp(ctx, "delete-service")
		os.Exit(1)
	}

	if id, err := strconv.ParseInt(ctx.Args().Get(0), 0, 64); err != nil {
		Fatalf("%s", err)
	} else {
		if err := client.DeleteServiceID(int64(id)); err != nil {
			Fatalf("%s", err)
		}
	}

	fmt.Printf("Successfully deleted\n")
}
