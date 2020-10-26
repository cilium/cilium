// Copyright 2017-2018 Authors of Cilium
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

	identityApi "github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	pkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// identityListCmd represents the identity_list command
var identityListCmd = &cobra.Command{
	Use:     "list [LABELS]",
	Aliases: []string{"ls"},
	Short:   "List identities",
	Run: func(cmd *cobra.Command, args []string) {
		listIdentities(args)
	},
}

func init() {
	identityCmd.AddCommand(identityListCmd)
	command.AddJSONOutput(identityListCmd)
	flags := identityListCmd.Flags()
	flags.Bool("endpoints", false, "list identities of locally managed endpoints")
	viper.BindPFlags(flags)
}

func listIdentities(args []string) {
	switch {
	case viper.GetBool("endpoints"):
		params := identityApi.NewGetIdentityEndpointsParams().WithTimeout(api.ClientTimeout)
		identities, err := client.Policy.GetIdentityEndpoints(params)
		if err != nil {
			Fatalf("Cannot get identities. err: %s", pkg.Hint(err))
		}
		// sort identities by ID
		im := identitymanager.IdentitiesModel(identities.Payload)
		sort.Slice(im, im.Less)
		printIdentitesEndpoints(identities.Payload)
	default:
		params := identityApi.NewGetIdentityParams().WithTimeout(api.ClientTimeout)
		if len(args) != 0 {
			params = params.WithLabels(args)
		}
		identities, err := client.Policy.GetIdentity(params)
		if err != nil {
			if params != nil {
				Fatalf("Cannot get identities for given labels %v. err: %s\n", params.Labels, err.Error())
			} else {
				Fatalf("Cannot get identities. err: %s", pkg.Hint(err))
			}
		}
		// sort identities by ID
		im := cache.IdentitiesModel(identities.Payload)
		sort.Slice(im, im.Less)
		printIdentities(identities.Payload)
	}
}

func printIdentitesEndpoints(identities []*models.IdentityEndpoints) {
	if command.OutputJSON() {
		if err := command.PrintOutput(identities); err != nil {
			Fatalf("Unable to provide JSON output: %s", err)
		}
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintf(w, "ID\tLABELS\tREFCOUNT\n")
	for _, identity := range identities {
		lbls := labels.NewLabelsFromModel(identity.Identity.Labels)
		first := true
		for _, lbl := range lbls.GetPrintableModel() {
			if first {
				fmt.Fprintf(w, "%d\t%s\t%d\t\n", identity.Identity.ID, lbl, identity.RefCount)
				first = false
			} else {
				fmt.Fprintf(w, "\t%s\t\n", lbl)
			}
		}
	}
	w.Flush()
}
