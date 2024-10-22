// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/authmap"
)

var bpfAuthFlushCmd = &cobra.Command{
	Use:     "flush",
	Short:   "Deletes all entries for authenticated connections between identities",
	Long:    "Deletes all entries for authenticated connections between identities",
	Aliases: []string{},
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf auth flush")

		authMap, err := authmap.LoadAuthMap()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Cannot find auth bpf map")
				return
			}

			Fatalf("Cannot load auth bpf map: %s", err)
		}

		entries := 0
		deleteEntry := func(key *authmap.AuthKey, _ *authmap.AuthInfo) {
			if key == nil {
				return
			}
			err := authMap.Delete(*key)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error deleting an auth map entry: %s\n", err)
				return
			}
			entries++
		}

		if err := authMap.IterateWithCallback(deleteEntry); err != nil {
			Fatalf("Error dumping contents of the auth map: %s\n", err)
		}

		fmt.Printf("Flushed %d entries\n", entries)
	},
}

func init() {
	BPFAuthCmd.AddCommand(bpfAuthFlushCmd)
	command.AddOutputOption(bpfAuthFlushCmd)
}
