// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/loadbalancer"
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

var clustermeshAffinity bool

func init() {
	serviceCmd.AddCommand(serviceListCmd)
	serviceListCmd.Flags().BoolVar(&clustermeshAffinity, "clustermesh-affinity", false, "Print clustermesh affinity if available")
	command.AddOutputOption(serviceListCmd)
}

func listServices(cmd *cobra.Command, args []string) {
	list, err := client.GetServices()
	if err != nil {
		Fatalf("Cannot get services list: %s", err)
	}

	if command.OutputOption() {
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
			var str string
			if clustermeshAffinity && be.Preferred {
				str = fmt.Sprintf("%d => %s (%s) (preferred)", i+1, beA.String(), be.State)
			} else {
				str = fmt.Sprintf("%d => %s (%s)", i+1, beA.String(), be.State)
			}
			backendAddresses = append(backendAddresses, str)
		}

		SvcOutput := ServiceOutput{
			ID:               svc.Status.Realized.ID,
			ServiceType:      svc.Spec.Flags.Type,
			FrontendAddress:  feA.String(),
			BackendAddresses: backendAddresses,
		}

		if svc.Spec.Flags.Cluster != "" {
			SvcOutput.ServiceType = SvcOutput.ServiceType + " (Remote)"
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
