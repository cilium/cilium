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
	"sort"
	"text/tabwriter"

	ipApi "github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	pkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

var ipListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List IP addresses in the userspace IPcache",
	Run: func(cmd *cobra.Command, args []string) {
		listIPs()
	},
}

func init() {
	ipCmd.AddCommand(ipListCmd)
	command.AddJSONOutput(ipListCmd)
	flags := ipListCmd.Flags()
	flags.BoolVarP(&verbose, "verbose", "v", false, "Print all fields of ipcache")
	viper.BindPFlags(flags)
}

func listIPs() {
	params := ipApi.NewGetIPParams().WithTimeout(api.ClientTimeout)
	ipcache, err := client.Policy.GetIP(params)
	if err != nil {
		Fatalf("Cannot get ipcache entries. err: %s", pkg.Hint(err))
	}
	im := ipcachetypes.IPListEntrySlice(ipcache.Payload)
	sort.Slice(im, im.Less)
	printIPcacheEntries(ipcache.Payload)
}

func printIPcacheEntries(entries []*models.IPListEntry) {
	if command.OutputJSON() {
		if err := command.PrintOutput(entries); err != nil {
			Fatalf("Unable to provide JSON output: %s", err)
		}
	} else {
		w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

		if verbose {
			fmt.Fprintf(w, "IP\tIDENTITY\tSOURCE\tHOST\tENCRYPT_KEY\n")
		} else {
			fmt.Fprintf(w, "IP\tIDENTITY\tSOURCE\n")
		}
		for _, entry := range entries {
			printEntry(w, entry, verbose)
		}

		w.Flush()
	}
}

func printEntry(w *tabwriter.Writer, entry *models.IPListEntry, verbose bool) {
	var src string
	if entry.Metadata != nil {
		src = entry.Metadata.Source
	}
	if verbose {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%d\n", *entry.Cidr, *entry.Identity, src, entry.HostIP, entry.EncryptKey)
	} else {
		fmt.Fprintf(w, "%s\t%d\t%s\n", *entry.Cidr, *entry.Identity, src)
	}
}
