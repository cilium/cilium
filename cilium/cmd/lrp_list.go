// Copyright 2020 Authors of Cilium
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
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"

	"github.com/spf13/cobra"
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
	command.AddJSONOutput(lrpListCmd)
}

func listLRPs(cmd *cobra.Command, args []string) {
	list, err := client.GetLRPs()
	if err != nil {
		Fatalf("Cannot get lrp list: %s", err)
	}

	if command.OutputJSON() {
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
