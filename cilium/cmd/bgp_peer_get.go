// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
)

var BgpPeersCmd = &cobra.Command{
	Use:   "peers",
	Short: "List current state of all peers",
	Long:  "List state of all peers defined in CiliumBGPPeeringPolicy",
	Run: func(cmd *cobra.Command, args []string) {
		res, err := client.Bgp.GetBgpPeers(nil)
		if err != nil {
			Fatalf("cannot get peers list: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(res.GetPayload()); err != nil {
				Fatalf("error getting output in JSON: %s\n", err)
			}
		} else {
			printSummary(res.GetPayload())
		}
	},
}

func printSummary(peers []*models.BgpPeer) {
	// get new tab writer with predefined defaults
	w := NewTabWriter()

	// sort by local AS, if peers from same AS then sort by peer address.
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].LocalAsn < peers[j].LocalAsn || peers[i].PeerAddress < peers[j].PeerAddress
	})

	fmt.Fprintln(w, "Local AS\tPeer AS\tPeer Address\tSession\tUptime\tFamily\tReceived\tAdvertised")
	for _, peer := range peers {
		fmt.Fprintf(w, "%d\t", peer.LocalAsn)
		fmt.Fprintf(w, "%d\t", peer.PeerAsn)
		fmt.Fprintf(w, "%s\t", peer.PeerAddress)
		fmt.Fprintf(w, "%s\t", peer.SessionState)

		// Time is rounded to nearest second
		fmt.Fprintf(w, "%s\t", time.Duration(peer.UptimeNanoseconds).Round(time.Second).String())

		for i, afisafi := range peer.Families {
			if i > 0 {
				// move by 5 tabs to align with afi-safi
				fmt.Fprint(w, strings.Repeat("\t", 5))
			}
			// AFI and SAFI are concatenated for brevity
			fmt.Fprintf(w, "%s/%s\t", afisafi.Afi, afisafi.Safi)
			fmt.Fprintf(w, "%d\t", afisafi.Received)
			fmt.Fprintf(w, "%d\t", afisafi.Advertised)
			fmt.Fprintf(w, "\n")
		}
	}
	w.Flush()
}

// NewTabWriter initialises tabwriter.Writer with following defaults
// width 5 and padding 3
func NewTabWriter() *tabwriter.Writer {
	minwidth := 5        // minimal cell width including any padding
	tabwidth := 0        // width of tab characters (equivalent number of spaces)
	padding := 3         // padding added to a cell before computing its width
	padChar := byte(' ') // ASCII char used for padding
	flags := uint(0)     // formatting control

	return tabwriter.NewWriter(os.Stdout, minwidth, tabwidth, padding, padChar, flags)
}

func init() {
	bgpCmd.AddCommand(BgpPeersCmd)
	command.AddOutputOption(BgpPeersCmd)
}
