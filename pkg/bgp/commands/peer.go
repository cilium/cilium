// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"cmp"
	"encoding/base64"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive/script"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bgp/agent"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/time"
)

func BGPPeersCmd(bgpMgr agent.BGPRouterManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List BGP peers on Cilium",
			Flags: func(fs *pflag.FlagSet) {
				addOutFileFlag(fs)
				addFormatFlag(fs)
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
				format, err := s.Flags.GetString(formatFlag)
				if err != nil {
					return "", "", err
				}

				res, err := bgpMgr.GetPeers(s.Context(), &agent.GetPeersRequest{})
				if err != nil {
					return "", "", err
				}

				w, buf, f, err := getCmdWriter(s)
				if err != nil {
					return "", "", err
				}
				if f != nil {
					defer f.Close()
				}

				switch format {
				case "table":
					tw := getCmdTabWriter(w)
					PrintPeerStatesTable(tw, res.Instances, noUptime)

					tw.Flush()
				case "detailed":
					PrintPeerStatesDetailed(w, res.Instances, noUptime)
				default:
					return "", "", fmt.Errorf("unsupported format: %s", format)
				}

				return buf.String(), "", err
			}, nil
		},
	)
}

func PrintPeerStatesTable(tw *tabwriter.Writer, instances []agent.InstancePeerStates, noUptime bool) {
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

	rows = slices.Insert(rows, 0, row{
		Instance:     "Instance",
		Peer:         "Peer",
		SessionState: "Session State",
		Uptime:       "Uptime",
		Family:       "Family",
		Received:     "Received",
		Accepted:     "Accepted",
		Advertised:   "Advertised",
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

			if row.Instance == "" && row.Peer == prevPeer {
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

			if row.Instance != "" {
				// Don't update prevPeer if Instance is deduplicated
				prevInstance = row.Instance
			}

			if row.Peer != "" {
				// Don't update prevPeer if Peer is deduplicated
				prevPeer = row.Peer
			}
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

func PrintPeerStatesDetailed(w io.Writer, instances []agent.InstancePeerStates, noUptime bool) {
	slices.SortFunc(instances, func(a, b agent.InstancePeerStates) int {
		return strings.Compare(a.Name, b.Name)
	})
	for _, instance := range instances {
		fmt.Fprintf(w, "Instance: %v\n", instance.Name)

		slices.SortFunc(instance.Peers, func(a, b types.PeerState) int {
			return strings.Compare(a.Name, b.Name)
		})
		for _, peer := range instance.Peers {
			fmt.Fprintf(w, "  Peer: %v\n", peer.Name)
			fmt.Fprintf(w, "    Address: %v\n", peer.Address)
			fmt.Fprintf(w, "    Port: %v\n", peer.Port)
			fmt.Fprintf(w, "    PeerAsn: %v\n", peer.PeerAsn)
			fmt.Fprintf(w, "    LocalAsn: %v\n", peer.LocalAsn)
			fmt.Fprintf(w, "    Session State: %v\n", peer.SessionState)

			if !noUptime {
				fmt.Fprintf(w, "    Uptime: %v\n", peer.Uptime.Truncate(time.Second).String())
			}

			slices.SortFunc(peer.Families, func(a, b types.PeerFamilyState) int {
				aStr := fmt.Sprintf("%s/%s", a.Afi, a.Safi)
				bStr := fmt.Sprintf("%s/%s", b.Afi, b.Safi)
				return strings.Compare(aStr, bStr)
			})
			for i, family := range peer.Families {
				if i == 0 {
					fmt.Fprintf(w, "    Address Families:\n")
				}

				fmt.Fprintf(w, "      %s/%s:\n", family.Afi, family.Safi)
				fmt.Fprintf(w, "        Received Routes: %v\n", family.ReceivedRoutes)
				fmt.Fprintf(w, "        Accepted Routes: %v\n", family.AcceptedRoutes)
				fmt.Fprintf(w, "        Advertised Routes: %v\n", family.AdvertisedRoutes)
			}

			fmt.Fprintf(w, "    Timers:\n")
			fmt.Fprintf(w, "      Hold Time:\n")
			fmt.Fprintf(w, "        Configured: %v\n", peer.Timers.ConfiguredHoldTime.Truncate(time.Second).String())
			fmt.Fprintf(w, "        Applied: %v\n", peer.Timers.AppliedHoldTime.Truncate(time.Second).String())
			fmt.Fprintf(w, "      Keep Alive Time:\n")
			fmt.Fprintf(w, "        Configured: %v\n", peer.Timers.ConfiguredKeepAliveTime.Truncate(time.Second).String())
			fmt.Fprintf(w, "        Applied: %v\n", peer.Timers.AppliedKeepAliveTime.Truncate(time.Second).String())
			fmt.Fprintf(w, "      Connect Retry Time: %v\n", peer.Timers.ConnectRetryTime.Truncate(time.Second).String())
			fmt.Fprintf(w, "    Ebgp Multihop TTL: %v\n", peer.EbgpMultihopTTL)
			fmt.Fprintf(w, "    Graceful Restart:\n")
			fmt.Fprintf(w, "      Enabled: %v\n", peer.GracefulRestart.Enabled)

			if peer.GracefulRestart.Enabled {
				fmt.Fprintf(w, "      Restart Time: %v\n", peer.GracefulRestart.RestartTime.Truncate(time.Second).String())
			}

			slices.SortFunc(peer.LocalCapabilities, func(a, b bgp.ParameterCapabilityInterface) int {
				c := cmp.Compare(a.Code(), b.Code())
				if c != 0 {
					return c
				}
				aByte, _ := a.Serialize()
				bByte, _ := b.Serialize()
				return strings.Compare(base64.StdEncoding.EncodeToString(aByte), base64.StdEncoding.EncodeToString(bByte))
			})
			for i, capability := range peer.LocalCapabilities {
				if i == 0 {
					fmt.Fprintf(w, "    Local Capabilities:\n")
				}

				if formatter, found := capabilityFormatters[capability.Code()]; found {
					formatter(w, capability)
				} else {
					formatDefaultCap(w, capability)
				}
			}

			slices.SortFunc(peer.RemoteCapabilities, func(a, b bgp.ParameterCapabilityInterface) int {
				return cmp.Compare(a.Code(), b.Code())
			})
			for i, capability := range peer.RemoteCapabilities {
				if i == 0 {
					fmt.Fprintf(w, "    Remote Capabilities:\n")
				}

				if formatter, found := capabilityFormatters[capability.Code()]; found {
					formatter(w, capability)
				} else {
					formatDefaultCap(w, capability)
				}
			}

			fmt.Fprintf(w, "    TCP Password Enabled: %v\n", peer.TCPPasswordEnabled)
		}
	}
}

// capabilityFormatter defines the function signature for a capability-specific printer.
type capabilityFormatter func(w io.Writer, cap bgp.ParameterCapabilityInterface)

// capabilityFormatters is a registry mapping BGP capability codes to their specific formatting functions.
var capabilityFormatters = map[bgp.BGPCapabilityCode]capabilityFormatter{
	bgp.BGP_CAP_MULTIPROTOCOL:               formatMultiProtocolCap,
	bgp.BGP_CAP_GRACEFUL_RESTART:            formatGracefulRestartCap,
	bgp.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART: formatLongLivedGracefulRestartCap,
	bgp.BGP_CAP_EXTENDED_NEXTHOP:            formatExtendedNexthopCap,
	bgp.BGP_CAP_ADD_PATH:                    formatAddPathCap,
	bgp.BGP_CAP_FQDN:                        formatFQDNCap,
	bgp.BGP_CAP_SOFT_VERSION:                formatSoftwareVersionCap,
}

func formatMultiProtocolCap(w io.Writer, cap bgp.ParameterCapabilityInterface) {
	fmt.Fprintf(w, "      %s:\n", cap.Code())
	m := cap.(*bgp.CapMultiProtocol)
	fmt.Fprintf(w, "        %s\n", m.CapValue)
}

func formatGracefulRestartCap(w io.Writer, cap bgp.ParameterCapabilityInterface) {
	fmt.Fprintf(w, "      %s", cap.Code())
	g := cap.(*bgp.CapGracefulRestart)
	if s := parseGracefulRestartCap(g); len(strings.TrimSpace(s)) > 0 {
		fmt.Fprintf(w, ":\n%s", s)
	} else {
		fmt.Fprintf(w, "\n")
	}
}

func formatLongLivedGracefulRestartCap(w io.Writer, cap bgp.ParameterCapabilityInterface) {
	fmt.Fprintf(w, "      %s", cap.Code())
	g := cap.(*bgp.CapLongLivedGracefulRestart)
	if s := parseLongLivedGracefulRestartCap(g); len(strings.TrimSpace(s)) > 0 {
		fmt.Fprintf(w, ":\n%s", s)
	} else {
		fmt.Fprintf(w, "\n")
	}
}

func formatExtendedNexthopCap(w io.Writer, cap bgp.ParameterCapabilityInterface) {
	fmt.Fprintf(w, "      %s", cap.Code())
	e := cap.(*bgp.CapExtendedNexthop)
	if s := parseExtendedNexthopCap(e); len(strings.TrimSpace(s)) > 0 {
		fmt.Fprintf(w, ":\n%s", s)
	} else {
		fmt.Fprintf(w, "\n")
	}
}

func formatAddPathCap(w io.Writer, cap bgp.ParameterCapabilityInterface) {
	fmt.Fprintf(w, "      %s:\n", cap.Code())
	for _, item := range cap.(*bgp.CapAddPath).Tuples {
		fmt.Fprintf(w, "        %s: %s\n", item.RouteFamily, item.Mode)
	}
}

func formatFQDNCap(w io.Writer, cap bgp.ParameterCapabilityInterface) {
	fmt.Fprintf(w, "      %s:\n", cap.Code())
	fqdn := cap.(*bgp.CapFQDN)
	fmt.Fprintf(w, "        name: %s\n        domain: %s\n", fqdn.HostName, fqdn.DomainName)
}

func formatSoftwareVersionCap(w io.Writer, cap bgp.ParameterCapabilityInterface) {
	fmt.Fprintf(w, "      %s: %s\n", cap.Code(), cap.(*bgp.CapSoftwareVersion).SoftwareVersion)
}

func formatDefaultCap(w io.Writer, cap bgp.ParameterCapabilityInterface) {
	fmt.Fprintf(w, "      %s\n", cap.Code())
}

func parseGracefulRestartCap(g *bgp.CapGracefulRestart) string {
	grStr := "        "
	if len(g.Tuples) > 0 {
		grStr += fmt.Sprintf("restart time: %d sec", g.Time)
	}
	if g.Flags&0x08 > 0 {
		if len(strings.TrimSpace(grStr)) > 0 {
			grStr += ", "
		}
		grStr += "restart flag set"
	}
	if g.Flags&0x04 > 0 {
		if len(strings.TrimSpace(grStr)) > 0 {
			grStr += ", "
		}
		grStr += "notification flag set"
	}

	if len(grStr) > 0 {
		grStr += "\n"
	}
	for _, t := range g.Tuples {
		grStr += fmt.Sprintf("        %s", bgp.AfiSafiToRouteFamily(t.AFI, t.SAFI))
		if t.Flags == 0x80 {
			grStr += ", forward flag set"
		}
		grStr += "\n"
	}
	return grStr
}

func parseLongLivedGracefulRestartCap(g *bgp.CapLongLivedGracefulRestart) string {
	var llgrStr strings.Builder
	for _, t := range g.Tuples {
		fmt.Fprintf(&llgrStr, "        %s, restart time %d sec", bgp.AfiSafiToRouteFamily(t.AFI, t.SAFI), t.RestartTime)
		if t.Flags == 0x80 {
			llgrStr.WriteString(", forward flag set")
		}
		llgrStr.WriteString("\n")
	}
	return llgrStr.String()
}

func parseExtendedNexthopCap(e *bgp.CapExtendedNexthop) string {
	lines := make([]string, 0, len(e.Tuples))
	for _, t := range e.Tuples {
		var nhafi string
		switch int(t.NexthopAFI) {
		case bgp.AFI_IP:
			nhafi = "ipv4"
		case bgp.AFI_IP6:
			nhafi = "ipv6"
		default:
			nhafi = fmt.Sprintf("%d", t.NexthopAFI)
		}
		line := fmt.Sprintf("        nlri: %s, nexthop: %s\n", bgp.AfiSafiToRouteFamily(t.NLRIAFI, uint8(t.NLRISAFI)), nhafi)
		lines = append(lines, line)
	}
	return strings.Join(lines, "")
}
