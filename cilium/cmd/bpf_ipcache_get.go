// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"os"
	"strings"

	iradix "github.com/hashicorp/go-immutable-radix/v2"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
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

		ip := net.ParseIP(arg)
		if ip == nil {
			Usagef(cmd, "Invalid ip address. "+usage)
		}

		bpfIPCache := dumpIPCache()

		if len(bpfIPCache) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
			os.Exit(1)
		}

		value, exists := getLPMValue(ip, bpfIPCache)

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
	bpfIPCacheCmd.AddCommand(bpfIPCacheGetCmd)
}

func dumpIPCache() map[string][]string {
	bpfIPCache := make(map[string][]string)

	if err := ipcache.IPCacheMap().Dump(bpfIPCache); err != nil {
		Fatalf("unable to dump IPCache: %s\n", err)
	}

	return bpfIPCache
}

// getLPMValue calculates the longest prefix matching ip amongst the
// keys in entries. The keys in entries must be specified in CIDR notation.
// If LPM is found, the value associated with that entry is returned
// along with boolean true. Otherwise, false is returned.
func getLPMValue(ip net.IP, entries map[string][]string) (interface{}, bool) {
	type lpmEntry struct {
		prefix   []byte
		identity []string
	}

	isV4 := isIPV4(ip)

	// Convert ip to 4-byte representation if IPv4.
	if isV4 {
		ip = ip.To4()
	}

	lpmEntries := make([]lpmEntry, 0, len(entries))
	for cidr, identity := range entries {
		currIP, subnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.WithError(err).Warnf("unable to parse ipcache entry %q as a CIDR", cidr)
			continue
		}

		// No need to include IPv6 addresses if the argument is
		// IPv4 and vice versa.
		if isIPV4(currIP) != isV4 {
			continue
		}

		// Convert ip to 4-byte representation if IPv4.
		if isV4 {
			currIP = currIP.To4()
		}

		ones, _ := subnet.Mask.Size()
		prefix := getPrefix(currIP, ones)

		lpmEntries = append(lpmEntries, lpmEntry{prefix, identity})
	}

	r := iradix.New[[]string]()
	for _, e := range lpmEntries {
		r, _, _ = r.Insert(e.prefix, e.identity)
	}

	// Look-up using all bits in the argument ip
	var mask int
	if isV4 {
		mask = 8 * net.IPv4len
	} else {
		mask = 8 * net.IPv6len
	}

	_, v, exists := r.Root().LongestPrefix(getPrefix(ip, mask))
	return v, exists
}

// getPrefix converts the most significant maskSize bits in ip
// into a byte slice - each bit is represented using one byte.
func getPrefix(ip net.IP, maskSize int) []byte {
	bytes := make([]byte, maskSize)
	var i, j uint8
	var n int

	for n < maskSize {
		for j = 0; j < 8 && n < maskSize; j++ {
			mask := uint8(128) >> uint8(j)

			if mask&ip[i] == 0 {
				bytes[i*8+j] = 0x0
			} else {
				bytes[i*8+j] = 0x1
			}
			n++
		}
		i++
	}

	return bytes
}

func isIPV4(ip net.IP) bool {
	return ip.To4() != nil
}
