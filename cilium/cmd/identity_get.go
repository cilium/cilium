// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	identityApi "github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/labels"
)

var (
	lookupLabels []string
)

func printIdentities(identities []*models.Identity) {
	if command.OutputOption() {
		if err := command.PrintOutput(identities); err != nil {
			Fatalf("Unable to provide %s output: %s", command.OutputOptionString(), err)
		}
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
	fmt.Fprintf(w, "ID\tLABELS\n")
	for _, identity := range identities {
		lbls := labels.NewLabelsFromModel(identity.Labels)
		first := true
		for _, lbl := range lbls.GetPrintableModel() {
			if first {
				fmt.Fprintf(w, "%d\t%s\n", identity.ID, lbl)
				first = false
			} else {
				fmt.Fprintf(w, "\t%s\n", lbl)
			}
		}
	}
	w.Flush()
}

// identityGetCmd represents the identity_get command
var identityGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Retrieve information about an identity",
	Run: func(cmd *cobra.Command, args []string) {
		if len(lookupLabels) > 0 {
			params := identityApi.NewGetIdentityParams().WithLabels(lookupLabels).WithTimeout(api.ClientTimeout)
			if id, err := client.Policy.GetIdentity(params); err != nil {
				Fatalf("Cannot get identity for labels %s: %s\n", lookupLabels, err)
			} else {
				printIdentities(id.Payload)
			}
		} else {
			if len(args) < 1 || args[0] == "" {
				Usagef(cmd, "Invalid identity ID")
			}

			params := identityApi.NewGetIdentityIDParams().WithID(args[0]).WithTimeout(api.ClientTimeout)
			if id, err := client.Policy.GetIdentityID(params); err != nil {
				Fatalf("Cannot get identity for given ID %s: %s\n", args[0], err)
			} else {
				printIdentities([]*models.Identity{id.Payload})
			}
		}
	},
}

func init() {
	identityCmd.AddCommand(identityGetCmd)
	identityGetCmd.Flags().StringSliceVar(&lookupLabels, "label", []string{}, "Label to lookup")
	command.AddOutputOption(identityGetCmd)
}
