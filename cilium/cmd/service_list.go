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
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/loadbalancer"

	"github.com/spf13/cobra"
)

// serviceListCmd represents the service_list command
var serviceListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List services",
	Run: func(cmd *cobra.Command, args []string) {
		listServices(cmd, args)
	},
}

func init() {
	serviceCmd.AddCommand(serviceListCmd)
	command.AddJSONOutput(serviceListCmd)
}

func listServices(cmd *cobra.Command, args []string) {
	list, err := client.GetServices()
	if err != nil {
		Fatalf("Cannot get services list: %s", err)
	}

	if command.OutputJSON() {
		if err := command.PrintOutput(list); err != nil {
			os.Exit(1)
		}
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	printServiceList(w, list)
}

func printServiceList(w *tabwriter.Writer, list []*models.Service) {
	fmt.Fprintln(w, "ID\tFrontend\tService Type\tBackend\t")

	type ServiceOutput struct {
		ID               int64
		ServiceType      string
		FrontendAddress  string
		BackendAddresses []string
	}
	svcs := []ServiceOutput{}

	for _, svc := range list {
		if svc.Status == nil || svc.Status.Realized == nil {
			fmt.Fprint(os.Stderr, "error parsing svc: empty state")
			continue
		}

		feA, err := loadbalancer.NewL3n4AddrFromModel(svc.Status.Realized.FrontendAddress)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing frontend %+v", svc.Status.Realized.FrontendAddress)
			continue
		}

		var backendAddresses []string
		for i, be := range svc.Status.Realized.BackendAddresses {
			beA, err := loadbalancer.NewL3n4AddrFromBackendModel(be)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error parsing backend %+v", be)
				continue
			}
			str := fmt.Sprintf("%d => %s", i+1, beA.String())
			backendAddresses = append(backendAddresses, str)
		}

		SvcOutput := ServiceOutput{
			ID:               svc.Status.Realized.ID,
			ServiceType:      svc.Spec.Flags.Type,
			FrontendAddress:  feA.String(),
			BackendAddresses: backendAddresses,
		}
		svcs = append(svcs, SvcOutput)
	}

	sort.Slice(svcs, func(i, j int) bool {
		return svcs[i].ID <= svcs[j].ID
	})

	for _, service := range svcs {
		var str string

		if len(service.BackendAddresses) == 0 {
			str = fmt.Sprintf("%d\t%s\t%s\t\t",
				service.ID, service.FrontendAddress, service.ServiceType)
			fmt.Fprintln(w, str)
			continue
		}

		str = fmt.Sprintf("%d\t%s\t%s\t%s\t",
			service.ID, service.FrontendAddress, service.ServiceType,
			service.BackendAddresses[0])
		fmt.Fprintln(w, str)

		for _, bkaddr := range service.BackendAddresses[1:] {
			str := fmt.Sprintf("\t\t\t%s\t", bkaddr)
			fmt.Fprintln(w, str)
		}
	}

	w.Flush()
}
