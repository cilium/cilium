// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"
	"sort"

	"github.com/spf13/cobra"

	identityApi "github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/identity/cache"
)

var (
	lookupLabels []string
)

func printIdentities(identities []*models.Identity) {
	im := cache.IdentitiesModel(identities)
	sort.Slice(im, im.Less)

	if command.OutputOption() {
		if err := command.PrintOutput(identities); err != nil {
			Fatalf("Unable to provide %s output: %s", command.OutputOptionString(), err)
		}
		return
	}

	cache.FormatIdentities(os.Stdout, identities)
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
	IdentityCmd.AddCommand(identityGetCmd)
	identityGetCmd.Flags().StringSliceVar(&lookupLabels, "label", []string{}, "Label to lookup")
	command.AddOutputOption(identityGetCmd)
}
