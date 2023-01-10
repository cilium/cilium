// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
)

// lrpListCmd represents the lrp_list command
var lrpListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List local redirect policies",
	Run: func(cmd *cobra.Command, args []string) {
		listLRPs(cmd, args)
	},
}

func init() {
	lrpCmd.AddCommand(lrpListCmd)
	command.AddOutputOption(lrpListCmd)
}

func listLRPs(cmd *cobra.Command, args []string) {
	list, err := client.GetLRPs()
	if err != nil {
		Fatalf("Cannot get lrp list: %s", err)
	}

	if command.OutputOption() {
		if err := command.PrintOutput(list); err != nil {
			os.Exit(1)
		}
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	printLRPList(w, list)
}

func getPrintableMapping(feM *models.FrontendMapping) string {
	var ret string
	ret = ret + fmt.Sprintf("%s:%d/%s -> ", feM.FrontendAddress.IP, feM.FrontendAddress.Port, feM.FrontendAddress.Protocol)
	for _, be := range feM.Backends {
		ret = ret + fmt.Sprintf("%s:%d(%s), ", *(be.BackendAddress.IP), be.BackendAddress.Port, be.PodID)
	}
	return ret
}

func printLRPList(w *tabwriter.Writer, list []*models.LRPSpec) {
	fmt.Fprintln(w, "LRP namespace\tLRP name\tFrontendType\tMatching Service")
	for _, lrp := range list {
		entry := fmt.Sprintf("%s\t%s\t%s\t%s", lrp.Namespace, lrp.Name, lrp.FrontendType, lrp.ServiceID)
		fmt.Fprintln(w, entry)
		for _, feM := range lrp.FrontendMappings {
			fmt.Fprintln(w, fmt.Sprintf("\t|\t%s", getPrintableMapping(feM)))
		}
	}
	w.Flush()
}
