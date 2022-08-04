// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	ipApi "github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	pkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/identity"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
)

var ipListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List IP addresses in the userspace IPcache",
	Run: func(cmd *cobra.Command, args []string) {
		listIPs()
	},
}

var numeric bool

func init() {
	ipCmd.AddCommand(ipListCmd)
	command.AddOutputOption(ipListCmd)
	flags := ipListCmd.Flags()
	flags.BoolVarP(&numeric, "numeric", "n", false, "Print numeric identities")
	flags.BoolVarP(&verbose, "verbose", "v", false, "Print all fields of ipcache")
	vp.BindPFlags(flags)
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
	if command.OutputOption() {
		if err := command.PrintOutput(entries); err != nil {
			Fatalf("Unable to provide %s output: %s", command.OutputOptionString(), err)
		}
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	if verbose {
		fmt.Fprintf(w, "IP\tIDENTITY\tSOURCE\tHOST\tENCRYPT_KEY\n")
	} else {
		fmt.Fprintf(w, "IP\tIDENTITY\tSOURCE\n")
	}
	for _, entry := range entries {
		printEntry(w, entry)
	}
	w.Flush()
}

func printEntry(w *tabwriter.Writer, entry *models.IPListEntry) {
	var src string
	if entry.Metadata != nil {
		src = entry.Metadata.Source
	}

	ni := identity.NumericIdentity(*entry.Identity)
	identityNumeric := ni.StringID()
	var identities []string
	if numeric {
		identities = append(identities, identityNumeric)
	} else {
		identity := ni.String()
		if identity != identityNumeric {
			identities = append(identities, identity)
		} else {
			params := ipApi.NewGetIdentityIDParams().WithID(identity).WithTimeout(api.ClientTimeout)
			id, err := client.Policy.GetIdentityID(params)
			if err != nil {
				Fatalf("Cannot get identity for given ID %s: %s\n", id, err)
			}
			lbls := labels.NewLabelsFromModel(id.Payload.Labels)
			for _, lbl := range lbls {
				identities = append(identities, lbl.String())
			}
		}
	}
	first := true
	for _, identity := range identities {
		if first {
			if verbose {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n", *entry.Cidr, identity, src, entry.HostIP, entry.EncryptKey)
			} else {
				fmt.Fprintf(w, "%s\t%s\t%s\n", *entry.Cidr, identity, src)
			}
			first = false
		} else {
			fmt.Fprintf(w, "\t%s\t\n", identity)
		}
	}
}
