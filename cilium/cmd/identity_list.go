// Copyright 2017 Authors of Cilium
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
	"encoding/json"
	"fmt"

	identityApi "github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/spf13/cobra"
)

// identityListCmd represents the identity_list command
var identityListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all identities",
	Run: func(cmd *cobra.Command, args []string) {
		listIdentities(args)
	},
}
var reservedIDs bool

func init() {
	identityCmd.AddCommand(identityListCmd)
	identityListCmd.Flags().BoolVarP(&reservedIDs, "reserved", "", false,
		"List all reserved identities")
}

func listIdentities(args []string) {
	if reservedIDs {
		fmt.Println("Reserved identities:")
		for k, v := range policy.ReservedIdentities {
			fmt.Printf("%3d %-15s \n", v, k)
		}
	}
	fmt.Println("Identities in use by endpoints:\n" +
		"(Note: If labels have been provided as parameters, only matching identities will be displayed)")

	var params *identityApi.GetIdentityParams
	if len(args) != 0 {
		params = identityApi.NewGetIdentityParams().WithLabels(args)
	}

	if identities, err := client.Policy.GetIdentity(params); err != nil {
		Fatalf("Cannot get identities for given labels %v. err: %s\n", params.Labels, err.Error())
	} else if b, err := json.MarshalIndent(identities, "", "  "); err != nil {
		Fatalf("Cannot marshal identities %s", err.Error())
	} else {
		fmt.Println(string(b))
	}
}
