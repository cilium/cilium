// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/cilium/hive/script"
	gobgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bgpv1/api"
	"github.com/cilium/cilium/pkg/bgpv1/gobgp"
	"github.com/cilium/cilium/pkg/bgpv1/types"
)

const (
	waitStateTimeout = 30 * time.Second

	serverASNFlag      = "server-asn"
	serverASNFlagShort = "s"

	routerIDFlag      = "router-id"
	routerIDFlagShort = "r"

	timeoutFlag      = "timeout"
	timeoutFlagShort = "t"

	passwordFlag      = "password"
	passwordFlagShort = "p"
)

type GoBGPCmdContext struct {
	servers map[uint32]*server.BgpServer
}

func NewGoBGPCmdContext() *GoBGPCmdContext {
	return &GoBGPCmdContext{
		servers: make(map[uint32]*server.BgpServer),
	}
}

func (ctx *GoBGPCmdContext) Cleanup() {
	for _, s := range ctx.servers {
		s.Stop()
	}
}

func GoBGPScriptCmds(ctx *GoBGPCmdContext) map[string]script.Cmd {
	return map[string]script.Cmd{
		"gobgp/add-server":    GoBGPAddServerCmd(ctx),
		"gobgp/delete-server": GoBGPDeleteServerCmd(ctx),
		"gobgp/add-peer":      GoBGPAddPeerCmd(ctx),
		"gobgp/wait-state":    GoBGPWaitStateCmd(ctx),
		"gobgp/peers":         GoBGPPeersCmd(ctx),
		"gobgp/routes":        GoBGPRoutesCmd(ctx),
	}
}

func GoBGPAddServerCmd(cmdCtx *GoBGPCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Add a new GoBGP server instance",
			Args:    "asn ip port",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP(routerIDFlag, routerIDFlagShort, "", "router-id of the server. Defaults to server ip if not provided.")
			},
			Detail: []string{
				"Add a new GoBGP server instance with the specified parameters.",
				"The server will be stopped during the test cleanup, but can be also removed during the test with gobgp/delete-server command.",
				"",
				"'ASN' is the autonomous system number of this instance.",
				"'ip' is the IP address on which the server listens for incoming connections.",
				"'port' is the port number on which the server listens for incoming connections.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 3 {
				return nil, fmt.Errorf("invalid command format, should be: 'gobgp/add-server asn ip port'")
			}
			asn, err := strconv.Atoi(args[0])
			if err != nil {
				return nil, fmt.Errorf("could not parse asn: %w", err)
			}
			port, err := strconv.Atoi(args[2])
			if err != nil {
				return nil, fmt.Errorf("could not parse port: %w", err)
			}
			routerID, err := s.Flags.GetString(routerIDFlag)
			if err != nil {
				return nil, err
			}
			if routerID == "" {
				routerID = args[1]
			}

			// start new GoBGP server
			gobgpServer := server.NewBgpServer(server.LoggerOption(gobgp.NewServerLogger(slog.Default(), gobgp.LogParams{
				AS:        uint32(asn),
				Component: "test",
				SubSys:    "gobgp",
			})))
			go gobgpServer.Serve()
			err = gobgpServer.StartBgp(s.Context(), &gobgpapi.StartBgpRequest{Global: &gobgpapi.Global{
				Asn:             uint32(asn),
				RouterId:        routerID,
				ListenAddresses: []string{args[1]},
				ListenPort:      int32(port),
			}})
			if err != nil {
				gobgpServer.Stop()
				return nil, err
			}
			cmdCtx.servers[uint32(asn)] = gobgpServer

			s.Logf("Started GoBGP Server ASN: %d, ip: %s, port: %d\n", asn, args[1], port)
			return nil, nil
		},
	)
}

func GoBGPDeleteServerCmd(cmdCtx *GoBGPCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Delete an existing GoBGP server instance",
			Args:    "asn",
			Detail: []string{
				"Delete an existing GoBGP server instance during the test run.",
				"",
				"'ASN' is the autonomous system number of the instance to be removed.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("invalid command format, should be: 'gobgp/delete-server asn'")
			}
			asn, err := strconv.Atoi(args[0])
			if err != nil {
				return nil, fmt.Errorf("could not parse asn: %w", err)
			}

			if gobgpServer, ok := cmdCtx.servers[uint32(asn)]; ok {
				gobgpServer.Stop()
				delete(cmdCtx.servers, uint32(asn))
				s.Logf("Stopped GoBGP Server ASN: %d\n", asn)
			} else {
				return nil, fmt.Errorf("GoBGP Server with asn: %d not found", asn)
			}
			return nil, nil
		},
	)
}

func GoBGPAddPeerCmd(cmdCtx *GoBGPCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Add a new peer the GoBGP server instance",
			Args:    "ip remote-asn",
			Flags: func(fs *pflag.FlagSet) {
				fs.Uint32P(serverASNFlag, serverASNFlagShort, 0, "ASN number of the GoBGP server instance. Can be omitted if only one instance is active.")
				fs.StringP(passwordFlag, passwordFlagShort, "", "Authentication password used for the peer.")
			},
			Detail: []string{
				"Add a new peer with the given IP and remote ASN to the GoBGP server instance.",
				"",
				"'ip' is IP address of the peer.",
				"'remote-asn' is the remote ASN number of the peer.",
				"If there are multiple server instances configured, the server-asn flag needs to be specified.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 2 {
				return nil, fmt.Errorf("invalid command format, should be: 'gobgp/ass-peer ip remote-asn'")
			}
			gobgpServer, err := getGoBGPServer(s, cmdCtx)
			if err != nil {
				return nil, err
			}

			peer := &gobgpapi.Peer{
				Conf: &gobgpapi.PeerConf{
					NeighborAddress: args[0],
				},
				Transport: &gobgpapi.Transport{
					PassiveMode: true,
				},
				AfiSafis: []*gobgpapi.AfiSafi{
					{
						Config: &gobgpapi.AfiSafiConfig{
							Family: &gobgpapi.Family{
								Afi:  gobgpapi.Family_AFI_IP,
								Safi: gobgpapi.Family_SAFI_UNICAST,
							},
						},
					},
					{
						Config: &gobgpapi.AfiSafiConfig{
							Family: &gobgpapi.Family{
								Afi:  gobgpapi.Family_AFI_IP6,
								Safi: gobgpapi.Family_SAFI_UNICAST,
							},
						},
					},
				},
				GracefulRestart: &gobgpapi.GracefulRestart{
					Enabled: true,
				},
			}
			_, err = fmt.Sscanf(args[1], "%d", &peer.Conf.PeerAsn)
			if err != nil {
				return nil, fmt.Errorf("could not parse remote-asn: %w", err)
			}

			password, err := s.Flags.GetString(passwordFlag)
			if err != nil {
				return nil, err
			}
			if password != "" {
				peer.Conf.AuthPassword = password
			}

			err = gobgpServer.AddPeer(s.Context(), &gobgpapi.AddPeerRequest{Peer: peer})
			if err != nil {
				return nil, fmt.Errorf("error by adding peer to server: %w", err)
			}
			s.Logf("Added peer to GoBGP Server: %+v\n", peer)
			return nil, nil
		},
	)
}

func GoBGPWaitStateCmd(cmdCtx *GoBGPCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Wait until the GoBGP peer is in the specified state",
			Args:    "peer state",
			Flags: func(fs *pflag.FlagSet) {
				fs.Uint32P(serverASNFlag, serverASNFlagShort, 0, "ASN number of the GoBGP server instance. Can be omitted if only one instance is active.")
				fs.DurationP(timeoutFlag, timeoutFlagShort, waitStateTimeout, "Maximum amount of time to wait for the peering state")
			},
			Detail: []string{
				"Wait until the specified peer is in the specified state.",
				"",
				"'peer' is IP address of a previously configured peer.",
				"'state' is one of: 'UNKNOWN', 'IDLE', 'CONNECT', 'ACTIVE', 'OPENSENT', 'OPENCONFIRM', 'ESTABLISHED'.",
				"If there are multiple server instances configured, the server-asn flag needs to be specified.",
				"The default wait timeout is 15 seconds.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 2 {
				return nil, fmt.Errorf("invalid command format, should be: 'gobgp/wait-state peer state'")
			}
			timeout, err := s.Flags.GetDuration("timeout")
			if err != nil {
				return nil, fmt.Errorf("could not parse timeout: %w", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			gobgpServer, err := getGoBGPServer(s, cmdCtx)
			if err != nil {
				return nil, err
			}

			doneCh := make(chan struct{})
			watchRequest := &gobgpapi.WatchEventRequest{
				Peer: &gobgpapi.WatchEventRequest_Peer{},
			}
			err = gobgpServer.WatchEvent(ctx, watchRequest, func(r *gobgpapi.WatchEventResponse) {
				if p := r.GetPeer(); p != nil && p.Type == gobgpapi.WatchEventResponse_PeerEvent_STATE {
					s.Logf("peer %s %s\n", p.Peer.Conf.NeighborAddress, p.Peer.State.SessionState)
					if p.Peer.State.SessionState == gobgpapi.PeerState_SessionState(gobgpapi.PeerState_SessionState_value[args[1]]) {
						if p.Peer.Conf.NeighborAddress == args[0] {
							doneCh <- struct{}{}
						}
					}
				}
			})
			if err != nil {
				return nil, err
			}
			// check if the peer isn't already in the expected state
			done := false
			err = gobgpServer.ListPeer(s.Context(), &gobgpapi.ListPeerRequest{Address: args[0]}, func(p *gobgpapi.Peer) {
				if p.State.SessionState == gobgpapi.PeerState_SessionState(gobgpapi.PeerState_SessionState_value[args[1]]) {
					done = true
				}
			})
			if err != nil {
				return nil, err
			}
			if done {
				return nil, nil
			}
			// wait for the expected state
			select {
			case <-s.Context().Done():
				return nil, s.Context().Err()
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-doneCh:
			}
			return nil, nil
		},
	)
}

func GoBGPPeersCmd(cmdCtx *GoBGPCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List peers on the GoBGP server",
			Flags: func(fs *pflag.FlagSet) {
				fs.Uint32P(serverASNFlag, serverASNFlagShort, 0, "ASN number of the GoBGP server instance. Can be omitted if only one instance is active.")
				addOutFileFlag(fs)
			},
			Detail: []string{
				"List peers configured on the GoBGP server",
				"",
				"If there are multiple server instances configured, the server-asn flag needs to be specified.",
			},
		},
		func(s *script.State, args ...string) (waitFunc script.WaitFunc, err error) {
			gobgpServer, err := getGoBGPServer(s, cmdCtx)
			if err != nil {
				return nil, err
			}
			return func(*script.State) (stdout, stderr string, err error) {
				tw, buf, f, err := getCmdTabWriter(s)
				if err != nil {
					return "", "", err
				}
				if f != nil {
					defer f.Close()
				}

				var peers []*gobgpapi.Peer
				err = gobgpServer.ListPeer(s.Context(), &gobgpapi.ListPeerRequest{EnableAdvertised: true}, func(p *gobgpapi.Peer) {
					peers = append(peers, p)
				})
				sort.Slice(peers, func(i, j int) bool {
					return peers[i].State.PeerAsn < peers[j].State.PeerAsn || peers[i].Conf.NeighborAddress < peers[j].Conf.NeighborAddress
				})

				printPeerHeader(tw)
				for _, peer := range peers {
					printPeer(tw, peer)
				}
				tw.Flush()
				return buf.String(), "", err
			}, nil
		},
	)
}

func GoBGPRoutesCmd(cmdCtx *GoBGPCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List routes on the GoBGP server",
			Args:    "[afi] [safi]",
			Flags: func(fs *pflag.FlagSet) {
				fs.Uint32P(serverASNFlag, serverASNFlagShort, 0, "ASN number of the GoBGP server instance. Can be omitted if only one instance is active.")
				addOutFileFlag(fs)
			},
			Detail: []string{
				"List all routes in the global RIB on the GoBGP server",
				"",
				"'afi' is Address Family Indicator, defaults to 'ipv4'.",
				"'safi' is Subsequent Address Family Identifier, defaults to 'unicast'.",
				"If there are multiple server instances configured, the server-asn flag needs to be specified.",
			},
		},
		func(s *script.State, args ...string) (waitFunc script.WaitFunc, err error) {
			gobgpServer, err := getGoBGPServer(s, cmdCtx)
			if err != nil {
				return nil, err
			}
			return func(*script.State) (stdout, stderr string, err error) {
				tw, buf, f, err := getCmdTabWriter(s)
				if err != nil {
					return "", "", err
				}
				if f != nil {
					defer f.Close()
				}

				req := &gobgpapi.ListPathRequest{
					TableType: gobgpapi.TableType_GLOBAL,
					Family: &gobgpapi.Family{
						Afi:  gobgpapi.Family_AFI_IP,
						Safi: gobgpapi.Family_SAFI_UNICAST,
					},
				}
				if len(args) > 0 && args[0] != "" {
					req.Family.Afi = gobgpapi.Family_Afi(types.ParseAfi(args[0]))
				}
				if len(args) > 1 && args[1] != "" {
					req.Family.Safi = gobgpapi.Family_Safi(types.ParseSafi(args[1]))
				}
				var paths []*gobgpapi.Destination
				err = gobgpServer.ListPath(s.Context(), req, func(dst *gobgpapi.Destination) {
					paths = append(paths, dst)
				})
				sort.Slice(paths, func(i, j int) bool {
					return paths[i].String() < paths[j].String()
				})

				printPathHeader(tw)
				for _, path := range paths {
					printPath(tw, path)
				}
				tw.Flush()
				return buf.String(), "", err
			}, nil
		},
	)
}

func getGoBGPServer(s *script.State, ctx *GoBGPCmdContext) (*server.BgpServer, error) {
	if len(ctx.servers) == 0 {
		return nil, fmt.Errorf("no GoBGP servers configured")
	}
	asn, err := s.Flags.GetUint32(serverASNFlag)
	if err != nil {
		return nil, fmt.Errorf("could not parse %s: %w", serverASNFlag, err)
	}
	if asn == 0 {
		// asn not specified
		if len(ctx.servers) > 1 {
			return nil, fmt.Errorf("multiple GoBGP servers are active, %s flag is required", serverASNFlag)
		} else {
			// only one server configured, return it
			for _, serv := range ctx.servers {
				return serv, nil
			}
		}
	}
	return ctx.servers[asn], nil
}

func printPeerHeader(w *tabwriter.Writer) {
	fmt.Fprintln(w, "PeerAddress\tRouterID\tPeerASN\tSessionState\tKeepAlive\tHoldTime\tGracefulRestartTime")
}

func printPeer(w *tabwriter.Writer, peer *gobgpapi.Peer) {
	fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%d\t%d\t%d\n", peer.Conf.NeighborAddress, peer.State.RouterId, peer.State.PeerAsn, peer.State.SessionState,
		peer.Timers.State.KeepaliveInterval, peer.Timers.State.NegotiatedHoldTime, peer.GracefulRestart.PeerRestartTime)
}

func printPathHeader(w *tabwriter.Writer) {
	fmt.Fprintln(w, "Prefix\tNextHop\tAttrs")
}

func printPath(w *tabwriter.Writer, dst *gobgpapi.Destination) {
	aPaths, _ := gobgp.ToAgentPaths(dst.Paths)
	for _, path := range aPaths {
		fmt.Fprintf(w, "%s\t%s\t%s\n", dst.Prefix, api.NextHopFromPathAttributes(path.PathAttributes), path.PathAttributes)
	}
}
