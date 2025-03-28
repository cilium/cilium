// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
)

var bpfIPCacheMatchCmd = &cobra.Command{
	Use:   "match",
	Short: "Retrieve identity for a prefix using an exact match",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ipcache match")

		if len(args) < 1 || args[0] == "" {
			Usagef(cmd, "No prefix provided")
		}

		arg := args[0]

		prefix, err := netip.ParsePrefix(arg)
		if err != nil {
			Usagef(cmd, "Invalid prefix: %s", err)
		}

		bpfIPCache := dumpIPCache()

		if len(bpfIPCache) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
			os.Exit(1)
		}

		value := getExactMatchValue(prefix, bpfIPCache)

		if len(value) == 0 {
			fmt.Printf("%s does not match to any ipcache entry\n", arg)
			os.Exit(1)
		}

		fmt.Printf("key %s has value %q\n", prefix, strings.Join(value, ","))
	},
}

func init() {
	BPFIPCacheCmd.AddCommand(bpfIPCacheMatchCmd)
}

func getExactMatchValue(prefix netip.Prefix, entries map[string][]string) []string {
	for key, value := range entries {
		if key == prefix.String() {
			return value
		}
	}

	return nil
}
