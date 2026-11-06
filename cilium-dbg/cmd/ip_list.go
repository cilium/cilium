// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"slices"
	"text/tabwriter"

	"github.com/spf13/cobra"

	ipApi "github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	pkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/identity"
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
	IPCmd.AddCommand(ipListCmd)
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
	sortIPListEntries(ipcache.Payload)
	printIPcacheEntries(ipcache.Payload)
}

// sortIPListEntries sorts entries by CIDR: IPv4 before IPv6, then by address,
// so that each prefix is directly followed by the narrower prefixes it
// contains.
func sortIPListEntries(entries []*models.IPListEntry) {
	slices.SortFunc(entries, func(a, b *models.IPListEntry) int {
		return a.Cidr.Compare(b.Cidr.Prefix)
	})
}

// Keep addresses textual for JSONPath without changing other fields' types or presence.
type ipListEntryOutput struct {
	Cidr       string                      `json:"cidr,omitzero"`
	EncryptKey int64                       `json:"encryptKey,omitempty"`
	HostIP     string                      `json:"hostIP,omitzero"`
	Identity   *int64                      `json:"identity"`
	Metadata   *models.IPListEntryMetadata `json:"metadata,omitempty"`
}

func formatIPListEntries(entries []*models.IPListEntry) []ipListEntryOutput {
	if entries == nil {
		return nil
	}
	output := make([]ipListEntryOutput, len(entries))
	for i, entry := range entries {
		output[i] = ipListEntryOutput{
			Cidr:       formatPrefix(entry.Cidr),
			EncryptKey: entry.EncryptKey,
			HostIP:     formatAddr(entry.HostIP),
			Identity:   entry.Identity,
			Metadata:   entry.Metadata,
		}
	}
	return output
}

func printIPcacheEntries(entries []*models.IPListEntry) {
	if command.OutputOption() {
		if err := command.PrintOutput(formatIPListEntries(entries)); err != nil {
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

func getLabels(ni identity.NumericIdentity) []string {
	params := ipApi.NewGetIdentityIDParams().WithID(ni.StringID()).WithTimeout(api.ClientTimeout)
	id, err := client.Policy.GetIdentityID(params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot get identity for ID %s: %s\n", ni.StringID(), err)
		return []string{ni.String()}
	}
	return labels.NewLabelsFromModel(id.Payload.Labels).GetPrintableModel()
}

func printEntry(w *tabwriter.Writer, entry *models.IPListEntry) {
	var src string
	if entry.Metadata != nil {
		src = entry.Metadata.Source
	}

	ni := identity.NumericIdentity(*entry.Identity)
	identityNumeric := ni.StringID()
	var labels []string
	if numeric {
		labels = append(labels, identityNumeric)
	} else {
		labels = append(labels, getLabels(ni)...)
	}
	first := true
	for _, lbl := range labels {
		if first {
			if verbose {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n", formatPrefix(entry.Cidr), lbl, src, formatAddr(entry.HostIP), entry.EncryptKey)
			} else {
				fmt.Fprintf(w, "%s\t%s\t%s\n", formatPrefix(entry.Cidr), lbl, src)
			}
			first = false
		} else {
			fmt.Fprintf(w, "\t%s\t\n", lbl)
		}
	}
}
