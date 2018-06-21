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
	identityApi "github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"
	pkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"

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
}

func listIdentities(args []string) {
	reserved := []*models.Identity{}
	identity.IterateReservedIdentities(func(k string, v identity.NumericIdentity) {
		reserved = append(reserved, identity.NewIdentity(v, labels.NewLabelsFromModel([]string{"reserved:" + k})).GetModel())
	})

	var params *identityApi.GetIdentityParams
	if len(args) != 0 {
		params = identityApi.NewGetIdentityParams().WithLabels(args)
	}

	identities, err := client.Policy.GetIdentity(params)
	if err != nil {
		if params != nil {
			Fatalf("Cannot get identities for given labels %v. err: %s\n", params.Labels, err.Error())
		} else {
			Fatalf("Cannot get identities. err: %s", pkg.Hint(err))
		}
	}

	if len(args) != 0 {
		printIdentities(identities.Payload)
	} else {
		printIdentities(append(reserved, identities.Payload...))
	}
}
