// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bgp/agent"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/time"
)

func BGPPPeersCmd(bgpMgr agent.BGPRouterManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List BGP peers on Cilium",
			Flags: func(fs *pflag.FlagSet) {
				addOutFileFlag(fs)
				fs.Bool("no-uptime", false, "Do not show Uptime for testing purpose")
			},
			Detail: []string{
				"List current state of all BGP peers configured in Cilium BGP Control Plane",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(*script.State) (stdout, stderr string, err error) {
				noUptime, err := s.Flags.GetBool("no-uptime")
				if err != nil {
					return "", "", err
				}

				tw, buf, f, err := getCmdTabWriter(s)
				if err != nil {
					return "", "", err
				}
				if f != nil {
					defer f.Close()
				}

				res, err := bgpMgr.GetPeers(s.Context(), &agent.GetPeersRequest{})
				if err != nil {
					return "", "", err
				}

				PrintPeerStates(tw, res.Instances, noUptime)

				tw.Flush()

				return buf.String(), "", err
			}, nil
		},
	)
}

func PrintPeerStates(tw *tabwriter.Writer, instances []agent.InstancePeerStates, noUptime bool) {
	type row struct {
		Instance     string
		Peer         string
		SessionState string
		Uptime       string
		Family       string
		Received     string
		Accepted     string
		Advertised   string
	}

	var rows []row

	rows = append(rows, row{
		Instance:     "Instance",
		Peer:         "Peer",
		SessionState: "Session State",
		Uptime:       "Uptime",
		Family:       "Family",
		Received:     "Received",
		Accepted:     "Accepted",
		Advertised:   "Advertised",
	})

	for _, instance := range instances {
		for _, peer := range instance.Peers {
			for _, family := range peer.Families {
				rows = append(rows, row{
					Instance:     instance.Name,
					Peer:         peer.Name,
					SessionState: peer.SessionState.String(),
					Uptime:       peer.Uptime.Truncate(time.Second).String(),
					Family:       family.String(),
					Received:     strconv.FormatUint(family.ReceivedRoutes, 10),
					Accepted:     strconv.FormatUint(family.AcceptedRoutes, 10),
					Advertised:   strconv.FormatUint(family.AdvertisedRoutes, 10),
				})
			}
		}
	}

	// Sort by Instance, Peer, Family for better deduplication
	slices.SortFunc(rows, func(a, b row) int {
		c := strings.Compare(a.Instance, b.Instance)
		if c != 0 {
			return c
		}
		c = strings.Compare(a.Peer, b.Peer)
		if c != 0 {
			return c
		}
		return strings.Compare(a.Family, b.Family)
	})

	prevInstance := ""
	prevPeer := ""
	for i, row := range rows {
		// Always print header
		if i != 0 {
			established := row.SessionState == types.SessionEstablished.String()

			// Deduplicate Instance name
			if row.Instance == prevInstance {
				row.Instance = ""
			}

			if row.Peer == prevPeer {
				// Deduplicate Peer name. Also per-peer information like
				// Session State and Uptime doesn't need to be repeated.
				row.Peer = ""
				row.SessionState = ""
				row.Uptime = ""
			} else if noUptime {
				// Hide Uptime if requested
				row.Uptime = "-"
			} else if !established {
				// Hide Uptime if session is not established
				row.Uptime = "-"
			}

			// Hide route counts if session is not established
			if !established {
				row.Received = "-"
				row.Accepted = "-"
				row.Advertised = "-"
			}

			prevInstance = row.Instance
			prevPeer = row.Peer
		}

		fmt.Fprintf(tw, "%s\n", strings.Join([]string{
			row.Instance,
			row.Peer,
			row.SessionState,
			row.Uptime,
			row.Family,
			row.Received,
			row.Accepted,
			row.Advertised,
		}, "\t"))
	}
}
