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
	"github.com/cilium/cilium/pkg/bgp/api"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/time"
)

func BGPRoutesCmd(bgpMgr agent.BGPRouterManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List BGP routes on Cilium",
			Args:    "<table type> <afi> <safi>",
			Flags: func(fs *pflag.FlagSet) {
				addOutFileFlag(fs)
				fs.Bool("no-age", false, "Do not show Age column for testing purpose")
			},
			Detail: []string{
				"List routes in the BGP Control Plane's RIBs",
				"",
				"table type: \"loc\" (loc-rib), \"in\" (adj-rib-in), or \"out\" (adj-rib-out).",
				"afi: Address Family Identifier (e.g. ipv4, ipv6).",
				"safi: Subsequent Address Family Identifier (e.g. unicast).",
				"peer name: optional, only for adj-rib-in/out.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 3 {
				return nil, fmt.Errorf("BGP routes command requires <table type> <afi> <safi>")
			}
			tableType, err := parseTableTypeArg(args[0])
			if err != nil {
				return nil, err
			}
			afi := types.ParseAfi(args[1])
			if afi == types.AfiUnknown {
				return nil, fmt.Errorf("unknown AFI %s", args[1])
			}
			safi := types.ParseSafi(args[2])
			if safi == types.SafiUnknown {
				return nil, fmt.Errorf("unknown SAFI %s", args[2])
			}
			req := &agent.GetRoutesRequest{
				TableType: tableType,
				Family: types.Family{
					Afi:  afi,
					Safi: safi,
				},
			}

			return func(*script.State) (stdout, stderr string, err error) {
				noAge, err := s.Flags.GetBool("no-age")
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

				res, err := bgpMgr.GetRoutes(s.Context(), req)
				if err != nil {
					return "", "", err
				}

				printPeer := tableType == types.TableTypeAdjRIBIn || tableType == types.TableTypeAdjRIBOut
				PrintRoutes(tw, res.Instances, printPeer, noAge)
				tw.Flush()

				return buf.String(), "", nil
			}, nil
		},
	)
}

func parseTableTypeArg(arg string) (types.TableType, error) {
	switch arg {
	case "loc":
		return types.TableTypeLocRIB, nil
	case "in":
		return types.TableTypeAdjRIBIn, nil
	case "out":
		return types.TableTypeAdjRIBOut, nil
	default:
		return types.TableTypeUnknown, fmt.Errorf("unknown table type %s", arg)
	}
}

func PrintRoutes(tw *tabwriter.Writer, instances []agent.InstanceRoutes, printPeer bool, noAge bool) {
	type row struct {
		Instance string
		Peer     string
		Prefix   string
		NextHop  string
		Best     string
		Age      string
	}

	var rows []row
	for _, instance := range instances {
		for _, route := range instance.Routes {
			for _, path := range route.Paths {
				r := row{
					Instance: instance.InstanceName,
					Peer:     instance.NeighborName,
					Prefix:   route.Prefix,
					NextHop:  api.NextHopFromPathAttributes(path.PathAttributes),
					Best:     strconv.FormatBool(path.Best),
					Age:      time.Duration(path.AgeNanoseconds).Truncate(time.Second).String(),
				}
				if noAge {
					r.Age = "-"
				}
				rows = append(rows, r)
			}
		}
	}

	slices.SortFunc(rows, func(a, b row) int {
		c := strings.Compare(a.Instance, b.Instance)
		if c != 0 {
			return c
		}
		c = strings.Compare(a.Peer, b.Peer)
		if c != 0 {
			return c
		}
		return strings.Compare(a.Prefix, b.Prefix)
	})

	rows = slices.Insert(rows, 0, row{
		Instance: "Instance",
		Peer:     "Peer",
		Prefix:   "Prefix",
		NextHop:  "NextHop",
		Best:     "Best",
		Age:      "Age",
	})

	prevInstance := ""
	prevPeer := ""
	prevPrefix := ""
	for i, row := range rows {
		if i != 0 {
			if row.Instance == prevInstance {
				row.Instance = ""
			}
			if row.Instance == "" && row.Peer == prevPeer {
				row.Peer = ""
			}
			if row.Instance == "" && row.Peer == "" && row.Prefix == prevPrefix {
				row.Prefix = ""
			}
		}

		if printPeer {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", row.Instance, row.Peer, row.Prefix, row.NextHop, row.Age)
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", row.Instance, row.Prefix, row.NextHop, row.Best, row.Age)
		}

		if row.Instance != "" {
			prevInstance = row.Instance
		}
		if row.Peer != "" {
			prevPeer = row.Peer
		}
		if row.Prefix != "" {
			prevPrefix = row.Prefix
		}
	}
}
