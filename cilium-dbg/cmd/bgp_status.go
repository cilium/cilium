// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/client/bgp"
	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bgpv1/api"
	"github.com/cilium/cilium/pkg/bgpv1/types"
)

var (
	requireAll bool
	requireAny bool
	showPeers  bool
)

// BgpStatusCmd represents the bgp status command
var BgpStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display BGP control plane status",
	Long: `Display the overall status of the BGP control plane and validate BGP peer connectivity.
	
This command can be used for:
- Viewing BGP control plane health status
- Validating BGP peer connect
ivity for readiness probes
- Automation and CI/CD integration with exit codes

Exit codes:
  0 - Success (BGP requirements met or validation passed)
  1 - Failure (BGP requirements not met or validation failed)`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runBgpStatusWithWriter(cmd.OutOrStdout()); err != nil {
			// The functions called by runBgpStatus print their own error messages.
			// We just need to exit with a non-zero code.
			os.Exit(1)
		}
	},
}

func init() {
	BgpCmd.AddCommand(BgpStatusCmd)
	BgpStatusCmd.Flags().BoolVar(&requireAll, "require-all", false, "Require all BGP peers to be in Established state")
	BgpStatusCmd.Flags().BoolVar(&requireAny, "require-any", false, "Require at least one BGP peer to be in Established state")
	BgpStatusCmd.Flags().BoolVar(&showPeers, "show-peers", false, "Show detailed information about BGP peers")
}

func newBGPTabWriterWithOutput(w io.Writer) *tabwriter.Writer {
	minwidth := 5
	tabwidth := 0
	padding := 3
	padChar := byte(' ')
	flags := uint(0)

	return tabwriter.NewWriter(w, minwidth, tabwidth, padding, padChar, flags)
}

func formatStatusState(state string) string {
	switch state {
	case models.BGPStatusStateOk:
		return "[OK]"
	case models.BGPStatusStateFailure:
		return "[FAILURE]"
	case models.BGPStatusStateWarning:
		return "[WARNING]"
	case models.BGPStatusStateDisabled:
		return "[DISABLED]"
	default:
		return state
	}
}

func getSessionStateIcon(state string) string {
	switch state {
	case types.SessionEstablished.String():
		return "[ESTABLISHED]"
	case "Idle":
		return "[IDLE]"
	case "Connect":
		return "[CONNECT]"
	case "Active":
		return "[ACTIVE]"
	case "OpenSent":
		return "[OPENSENT]"
	case "OpenConfirm":
		return "[OPENCONFIRM]"
	default:
		return "[UNKNOWN]"
	}
}

// runBgpStatus is a wrapper for backward compatibility
func runBgpStatus() error {
	return runBgpStatusWithWriter(os.Stdout)
}

func runBgpStatusWithWriter(w io.Writer) error {
	// Get overall BGP status from daemon
	statusParams := daemon.NewGetHealthzParams()
	statusResp, err := client.Daemon.GetHealthz(statusParams)
	if err != nil {
		return fmt.Errorf("cannot get daemon status: %w", err)
	}

	bgpStatus := statusResp.Payload.BgpStatus
	if bgpStatus == nil {
		fmt.Fprintln(w, "BGP Control Plane is not available")
		return errors.New("BGP control plane not available")
	}

	// Get detailed peer information if needed
	var peers []*models.BgpPeer
	if showPeers || requireAll || requireAny {
		peerResp, err := client.Bgp.GetBgpPeers(nil)
		if err != nil {
			disabledErr := bgp.NewGetBgpPeersDisabled()
			if errors.As(err, &disabledErr) {
				fmt.Fprintln(w, "BGP Control Plane is disabled")
				return nil 
			}
			return fmt.Errorf("cannot get peers list: %w", err)
		}
		peers = peerResp.GetPayload()
	}

	fmt.Fprintf(w, "BGP Control Plane Status: %s\n", formatStatusState(bgpStatus.State))
	if bgpStatus.Msg != "" {
		fmt.Fprintf(w, "Message: %s\n", bgpStatus.Msg)
	}
	if bgpStatus.Mode != "" {
		fmt.Fprintf(w, "Readiness Mode: %s\n", bgpStatus.Mode)
	}

	if !requireAll && !requireAny && !showPeers && len(peers) == 0 {
		// Get basic peer info even for summary if we don't have detailed peers
		peerResp, err := client.Bgp.GetBgpPeers(nil)
		if err == nil {
			peers = peerResp.GetPayload()
		}
	}

	if requireAny {
		if err := validateAnyPeerWithWriter(w, peers); err != nil {
			return err
		}
	}

	if requireAll {
		if err := validateAllPeersWithWriter(w, peers); err != nil {
			return err
		}
	}

	if showPeers {
		displayPeerDetailsWithWriter(w, peers)
	} else if !requireAll && !requireAny {
		displayPeerSummaryWithWriter(w, peers, bgpStatus)
	}
	return nil
}

func validateAnyPeerWithWriter(w io.Writer, peers []*models.BgpPeer) error {
	if len(peers) == 0 {
		fmt.Fprintln(w, "\nValidation: No BGP peers configured")
		return errors.New("no BGP peers configured")
	}

	establishedCount := 0
	var notEstablishedPeers []string

	for _, peer := range peers {
		if peer == nil {
			continue // Skip nil peers
		}
		if peer.SessionState == types.SessionEstablished.String() {
			establishedCount++
		} else {
			peerAddr := peer.PeerAddress
			if peerAddr == "" {
				peerAddr = "unknown"
			}
			notEstablishedPeers = append(notEstablishedPeers,
				fmt.Sprintf("%s (AS %d)", peerAddr, peer.PeerAsn))
		}
	}

	fmt.Fprintf(w, "\n BGP Peer Validation (require-any) \n")
	fmt.Fprintf(w, "Total peers: %d\n", len(peers))
	fmt.Fprintf(w, "Established: %d\n", establishedCount)
	fmt.Fprintf(w, "Not established: %d\n", len(notEstablishedPeers))
	fmt.Fprintf(w, "\n")

	if establishedCount > 0 {
		fmt.Fprintf(w, "[SUCCESS] At least one BGP peer is established\n")
		if len(notEstablishedPeers) > 0 {
			fmt.Fprintf(w, "\nNote: Some peers are not established:\n")
			for _, peer := range notEstablishedPeers {
				fmt.Fprintf(w, "  - %s\n", peer)
			}
		}
	} else {
		fmt.Fprintf(w, "[FAILURE] No BGP peers are established\n")
		fmt.Fprintf(w, "\nAll peers are not established:\n")
		for _, peer := range notEstablishedPeers {
			fmt.Fprintf(w, "  - %s\n", peer)
		}
		return errors.New("no BGP peers are established")
	}
	return nil
}

func validateAllPeersWithWriter(w io.Writer, peers []*models.BgpPeer) error {
	if len(peers) == 0 {
		fmt.Fprintln(w, "\nValidation: No BGP peers configured")
		return nil 
	}

	establishedCount := 0
	var notEstablishedPeers []string

	for _, peer := range peers {
		if peer == nil {
			continue 
		}
		if peer.SessionState == types.SessionEstablished.String() {
			establishedCount++
		} else {
			peerAddr := peer.PeerAddress
			if peerAddr == "" {
				peerAddr = "unknown"
			}
			notEstablishedPeers = append(notEstablishedPeers,
				fmt.Sprintf("%s (AS %d)", peerAddr, peer.PeerAsn))
		}
	}

	fmt.Fprintf(w, "\n BGP Peer Validation (require-all) \n")
	fmt.Fprintf(w, "Total peers: %d\n", len(peers))
	fmt.Fprintf(w, "Established: %d\n", establishedCount)
	fmt.Fprintf(w, "Not established: %d\n", len(notEstablishedPeers))
	fmt.Fprintf(w, "\n")

	if len(notEstablishedPeers) == 0 {
		fmt.Fprintf(w, "[SUCCESS] All BGP peers are established\n")
	} else {
		fmt.Fprintf(w, "[FAILURE] Not all BGP peers are established\n")
		fmt.Fprintf(w, "\nNot established peers:\n")
		for _, peer := range notEstablishedPeers {
			fmt.Fprintf(w, "  - %s\n", peer)
		}
		return errors.New("not all BGP peers are established")
	}
	return nil
}

func displayPeerDetailsWithWriter(w io.Writer, peers []*models.BgpPeer) {
	if len(peers) == 0 {
		fmt.Fprintln(w, "\nNo BGP peers configured")
		return
	}

	fmt.Fprintf(w, "\nBGP Peer Details:\n")
	tw := newBGPTabWriterWithOutput(w)
	api.PrintBGPPeersTable(tw, peers, true)
	tw.Flush()
}

func displayPeerSummaryWithWriter(w io.Writer, peers []*models.BgpPeer, bgpStatus *models.BGPStatus) {
	if len(peers) == 0 {
		// Try to get peer count from status message
		fmt.Fprintf(w, "\nPeer Summary: %s\n", bgpStatus.Msg)
		return
	}

	establishedCount := 0
	sessionStates := make(map[string]int)

	for _, peer := range peers {
		if peer == nil {
			continue
		}
		if peer.SessionState == types.SessionEstablished.String() {
			establishedCount++
		}
		sessionStates[peer.SessionState]++
	}

	fmt.Fprintf(w, "\n Peer Summary \n")
	fmt.Fprintf(w, "Total peers: %d\n", len(peers))
	fmt.Fprintf(w, "Established: %d\n", establishedCount)

	if len(sessionStates) > 1 || (len(sessionStates) == 1 && sessionStates[types.SessionEstablished.String()] == 0) {
		fmt.Fprintf(w, "\nSession states breakdown:\n")

		// Sort states for consistent output
		states := make([]string, 0, len(sessionStates))
		for state := range sessionStates {
			states = append(states, state)
		}
		sort.Strings(states)

		for _, state := range states {
			count := sessionStates[state]
			stateIcon := getSessionStateIcon(state)
			fmt.Fprintf(w, "  %s %s: %d\n", stateIcon, state, count)
		}
	}

	fmt.Fprintf(w, "\nOverall Status: ")
	if establishedCount == len(peers) {
		fmt.Fprintf(w, "[OK] All peers established\n")
	} else if establishedCount > 0 {
		fmt.Fprintf(w, "[WARNING] Some peers established (%d/%d)\n", establishedCount, len(peers))
	} else {
		fmt.Fprintf(w, "[FAILURE] No peers established\n")
	}
}
