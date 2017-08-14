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
	"github.com/cilium/cilium/pkg/policy"

	identityApi "github.com/cilium/cilium/api/v1/client/policy"

	"github.com/spf13/cobra"
)

var listID bool

// identityGetCmd represents the identity_get command
var identityGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Retrieve the identity of the specified label",
	Run: func(cmd *cobra.Command, args []string) {
		if listID {
			for k, v := range policy.ReservedIdentities {
				fmt.Printf("%-15s %3d\n", k, v)
			}
			return
		}

		if len(args) < 1 || args[0] == "" {
			Usagef(cmd, "Invalid identity ID")
		}

		if id := policy.GetReservedID(args[0]); id != policy.ID_UNKNOWN {
			fmt.Printf("%d\n", id)
		} else {
			params := identityApi.NewGetIdentityIDParams().WithID(args[0])
			if id, err := client.Policy.GetIdentityID(params); err != nil {
				Fatalf("Cannot get identity for given ID %s: %s\n", id, err)
			} else if b, err := json.MarshalIndent(id, "", "  "); err != nil {
				Fatalf("Cannot marshal identity %s", err.Error())
			} else {
				fmt.Println(string(b))
			}
		}
	},
}

func init() {
	identityCmd.AddCommand(identityGetCmd)
	identityGetCmd.Flags().BoolVarP(&listID, "list", "", false, "List all identities")
}
