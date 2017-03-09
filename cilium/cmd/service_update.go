// Copyright 2017 Authors of Cilium
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

package cmd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/types"

	"github.com/spf13/cobra"
)

var (
	addRev   bool
	idU      uint64
	frontend string
	backends []string
)

// serviceUpdateCmd represents the service_update command
var serviceUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		updateService(cmd, args)
	},
}

func init() {
	serviceCmd.AddCommand(serviceUpdateCmd)
	serviceUpdateCmd.Flags().BoolVarP(&addRev, "rev", "", true, "Add reverse translation")
	serviceUpdateCmd.Flags().Uint64VarP(&idU, "id", "", 0, "Identifier")
	serviceUpdateCmd.Flags().StringVarP(&frontend, "frontend", "", "", "Frontend address")
	serviceUpdateCmd.Flags().StringSliceVarP(&backends, "backends", "", []string{}, "Backend address or addresses followed by optional weight (<IP:Port>[/weight])")
}

func parseFrontendAddress(address string) (*models.FrontendAddress, net.IP) {
	frontend, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		Fatalf("Unable to parse frontend address: %s\n", err)
	}

	// FIXME support more than TCP
	return &models.FrontendAddress{
		IP:       frontend.IP.String(),
		Port:     uint16(frontend.Port),
		Protocol: models.FrontendAddressProtocolTCP,
	}, frontend.IP
}

func updateService(cmd *cobra.Command, args []string) {
	id := int64(idU)
	fa, faIP := parseFrontendAddress(frontend)

	svc := &models.Service{
		ID:               id,
		FrontendAddress:  fa,
		BackendAddresses: []*models.BackendAddress{},
		Flags: &models.ServiceFlags{
			DirectServerReturn: addRev,
		},
	}

	if len(backends) == 0 {
		fmt.Printf("Reading backend list from stdin...\n")

		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			backends = append(backends, scanner.Text())
		}
	}

	for _, backend := range backends {
		tmp := strings.Split(backend, "/")
		if len(tmp) > 2 {
			Fatalf("Incorrect backend specification %s\n", backend)
		}
		addr := tmp[0]
		weight := uint64(0)
		if len(tmp) == 2 {
			var err error
			weight, err = strconv.ParseUint(tmp[1], 10, 16)
			if err != nil {
				Fatalf("Error converting weight %s\n", err)
			}
		}
		beAddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			Fatalf("Cannot parse backend address \"%s\": %s", backend, err)
		}

		be, err := types.NewLBBackEnd(types.TCP, beAddr.IP, uint16(beAddr.Port), uint16(weight))
		if err != nil {
			Fatalf("Unable to create a new L3n4Addr for backend %s: %s", backend, err)
		}

		if be.IsIPv6() && faIP.To4() != nil {
			Fatalf("Address mismatch between frontend and backend %s", backend)
		}

		if fa.Port == 0 && beAddr.Port != 0 {
			Fatalf("L4 backend found (%v) with L3 frontend", beAddr)
		}

		ba := be.GetBackendModel()
		svc.BackendAddresses = append(svc.BackendAddresses, ba)
	}

	if created, err := client.PutServiceID(id, svc); err != nil {
		Fatalf("Cannot add/update service: %s", err)
	} else if created {
		fmt.Printf("Added service with %d backends\n", len(svc.BackendAddresses))
	} else {
		fmt.Printf("Updated service with %d backends\n", len(svc.BackendAddresses))
	}
}
