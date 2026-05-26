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
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ipcache"
)

const usage = "IP address must be in dotted decimal (192.168.1.1) or IPv6 (feab::f02b) form"

var bpfIPCacheGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Retrieve identity for an ip",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ipcache get")

		if len(args) < 1 || args[0] == "" {
			Usagef(cmd, "No ip provided. "+usage)
		}

		arg := args[0]

		ip, err := netip.ParseAddr(arg)
		if err != nil {
			Usagef(cmd, "Invalid ip address. "+usage)
		}

		bpfIPCache := dumpIPCache()

		if len(bpfIPCache) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
			os.Exit(1)
		}

		value, exists := getLPMValue(ip.Unmap(), bpfIPCache)

		if !exists {
			fmt.Printf("%s does not map to any identity\n", arg)
			os.Exit(1)
		}

		v := value.([]string)
		if len(v) == 0 {
			fmt.Printf("Unable to retrieve identity for LPM entry %s\n", arg)
			os.Exit(1)
		}

		ids := strings.Join(v, ",")
		fmt.Printf("%s maps to identity %s\n", arg, ids)
	},
}

func init() {
	BPFIPCacheCmd.AddCommand(bpfIPCacheGetCmd)
}

func dumpIPCache() map[string][]string {
	bpfIPCache := make(map[string][]string)

	if err := ipcache.IPCacheMap(nil).Dump(bpfIPCache); err != nil {
		Fatalf("unable to dump IPCache: %s\n", err)
	}

	return bpfIPCache
}

// getLPMValue calculates the longest prefix matching ip amongst the
// keys in entries. The keys in entries must be specified in CIDR notation.
// If LPM is found, the value associated with that entry is returned
// along with boolean true. Otherwise, false is returned.
func getLPMValue(ip netip.Addr, entries map[string][]string) (any, bool) {
	var (
		value   []string
		longest = -1
		found   bool
	)

	for cidr, identity := range entries {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			log.Warn(
				"unable to parse ipcache entry as a CIDR",
				logfields.Error, err,
				logfields.Entry, cidr,
			)
			continue
		}

		prefix = prefix.Masked()

		// No need to include IPv6 addresses if the argument is
		// IPv4 and vice versa.
		if prefix.Addr().Is4() != ip.Is4() {
			continue
		}

		if prefix.Contains(ip) && prefix.Bits() > longest {
			value = identity
			longest = prefix.Bits()
			found = true
		}
	}

	return value, found
}
