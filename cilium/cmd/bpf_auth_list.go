// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/policy"
)

type authEntry struct {
	LocalIdentity  uint32
	RemoteIdentity uint32
	RemoteNodeID   uint16
	AuthType       uint8
	Expiration     time.Time
}

var bpfAuthListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all authenticated connections between identities",
	Long:    "List all authenticated connections between identities",
	Aliases: []string{"ls"},
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf auth list")

		authMap, err := authmap.LoadAuthMap()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Cannot find auth bpf map")
				return
			}

			Fatalf("Cannot load auth bpf map: %s", err)
		}

		var bpfAuthList []authEntry
		parse := func(key *authmap.AuthKey, val *authmap.AuthInfo) {

			bpfAuthList = append(bpfAuthList, authEntry{
				LocalIdentity:  key.LocalIdentity,
				RemoteIdentity: key.RemoteIdentity,
				RemoteNodeID:   key.RemoteNodeID,
				AuthType:       key.AuthType,
				Expiration:     val.Expiration.Time(),
			})
		}

		if err := authMap.IterateWithCallback(parse); err != nil {
			Fatalf("Error dumping contents of the auth map: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfAuthList); err != nil {
				Fatalf("error getting output of map in JSON: %s\n", err)
			}
			return
		}

		if len(bpfAuthList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			printAuthList(bpfAuthList)
		}
	},
}

func printAuthList(authList []authEntry) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	fmt.Fprintln(w, "SRC IDENTITY\tDST IDENTITY\tREMOTE NODE ID\tAUTH TYPE\tEXPIRATION")
	for _, a := range authList {
		fmt.Fprintf(w, "%d\t%d\t%d\t%s\t%s\n", a.LocalIdentity, a.RemoteIdentity, a.RemoteNodeID, policy.AuthType(a.AuthType), a.Expiration)
	}

	w.Flush()
}

func init() {
	bpfAuthCmd.AddCommand(bpfAuthListCmd)
	command.AddOutputOption(bpfAuthListCmd)
}
