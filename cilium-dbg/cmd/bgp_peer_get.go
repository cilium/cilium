// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/client/bgp"
	"github.com/cilium/cilium/pkg/bgpv1/api"
	"github.com/cilium/cilium/pkg/command"
)

var BgpPeersCmd = &cobra.Command{
	Use:     "peers",
	Aliases: []string{"neighbors"},
	Short:   "List current state of all peers",
	Long:    "List state of all peers defined in CiliumBGPPeeringPolicy",
	Run: func(cmd *cobra.Command, args []string) {
		res, err := client.Bgp.GetBgpPeers(nil)
		if err != nil {
			disabledErr := bgp.NewGetBgpPeersDisabled()
			if errors.As(err, &disabledErr) {
				fmt.Println("BGP Control Plane is disabled")
				return
			}
			Fatalf("cannot get peers list: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(res.GetPayload()); err != nil {
				Fatalf("error getting output in JSON: %s\n", err)
			}
		} else {
			w := NewTabWriter()
			api.PrintBGPPeersTable(w, res.GetPayload(), true)
		}
	},
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
	BgpCmd.AddCommand(BgpPeersCmd)
	command.AddOutputOption(BgpPeersCmd)
}
