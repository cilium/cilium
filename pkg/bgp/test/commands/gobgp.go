// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cilium/hive/script"
	gobgpapi "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgpconfig "github.com/osrg/gobgp/v4/pkg/config"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bgp/api"
	"github.com/cilium/cilium/pkg/bgp/gobgp"
	"github.com/cilium/cilium/pkg/bgp/types"
)

const (
	waitStateTimeout = 30 * time.Second

	serverNameFlag      = "server-name"
	serverNameFlagShort = "s"

	timeoutFlag      = "timeout"
	timeoutFlagShort = "t"

	gobgpSessionStatePrefix = "SESSION_STATE_"
)

// gobgpServerState tracks a running GoBGP test server instance together with
// the last GoBGP configuration successfully applied to it, so that
// gobgp/reload-server can diff a new configuration against it.
type gobgpServerState struct {
	server *server.BgpServer
	config *oc.BgpConfigSet
}

type GoBGPCmdContext struct {
	servers map[string]*gobgpServerState
}

func NewGoBGPCmdContext() *GoBGPCmdContext {
	return &GoBGPCmdContext{
		servers: make(map[string]*gobgpServerState),
	}
}

func (ctx *GoBGPCmdContext) AddServer(name string, srv *server.BgpServer, config *oc.BgpConfigSet) {
	if _, found := ctx.servers[name]; found {
		panic("Server " + name + " already exists")
	}
	ctx.servers[name] = &gobgpServerState{server: srv, config: config}
}

func (ctx *GoBGPCmdContext) DeleteServer(name string) {
	if _, found := ctx.servers[name]; !found {
		return
	}
	delete(ctx.servers, name)
}

func (ctx *GoBGPCmdContext) NServers() int {
	return len(ctx.servers)
}

func (ctx *GoBGPCmdContext) GetServer(name string) (*server.BgpServer, bool) {
	if name == "" {
		if ctx.NServers() > 0 {
			// Return fierst server if no name is specified
			for _, state := range ctx.servers {
				return state.server, true
			}
		} else {
			return nil, false
		}
	}
	state, found := ctx.servers[name]
	if !found {
		return nil, false
	}
	return state.server, true
}

func (ctx *GoBGPCmdContext) Cleanup() {
	for _, state := range ctx.servers {
		state.server.Stop()
	}
}

func GoBGPScriptCmds(ctx *GoBGPCmdContext) map[string]script.Cmd {
	return map[string]script.Cmd{
		"gobgp/add-server":      GoBGPAddServerCmd(ctx),
		"gobgp/delete-server":   GoBGPDeleteServerCmd(ctx),
		"gobgp/reload-server":   GoBGPReloadServerCmd(ctx),
		"gobgp/wait-state":      GoBGPWaitStateCmd(ctx),
		"gobgp/peers":           GoBGPPeersCmd(ctx),
		"gobgp/routes":          GoBGPRoutesCmd(ctx),
		"gobgp/advertise-route": GoBGPAdvertiseRouteCmd(ctx),
	}
}

func GoBGPAddServerCmd(cmdCtx *GoBGPCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Add a new GoBGP server instance from a native GoBGP configuration file",
			Args:    "name config-file",
			Detail: []string{
				"Add a new GoBGP server instance. The <config-file> argument specifies an initial",
				"configuration file. The format is the same as the one of upstream gobgpd.",
				"",
				"'name' is the name used to refer to this server instance in other gobgp/* commands.",
				"'config-file' is a path to an initial configuration file. The format is the same as",
				"the one of the upstream gobgpd consumes.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 2 {
				return nil, fmt.Errorf("invalid command format, should be: 'gobgp/add-server name config-file'")
			}
			path := s.Path(args[1])
			configSet, err := gobgpconfig.ReadConfigFile(path, "")
			if err != nil {
				return nil, fmt.Errorf("could not read GoBGP config file %s: %w", args[1], err)
			}

			// start new GoBGP server
			logger := slog.Default().With(
				types.ComponentLogField, "gobgp-server",
				types.NameLogField, args[0],
			)
			gobgpServer := server.NewBgpServer(server.LoggerOption(logger, nil))
			go gobgpServer.Serve()
			appliedConfig, err := gobgpconfig.InitialConfig(s.Context(), gobgpServer, configSet, false)
			if err != nil {
				gobgpServer.Stop()
				return nil, err
			}
			cmdCtx.AddServer(args[0], gobgpServer, appliedConfig)

			s.Logf("Started GoBGP Server %q\n", args[0])

			return nil, nil
		},
	)
}

func GoBGPDeleteServerCmd(cmdCtx *GoBGPCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Delete an existing GoBGP server instance",
			Args:    "name",
			Detail: []string{
				"Delete an existing GoBGP server instance during the test run.",
				"",
				"'ASN' is the autonomous system number of the instance to be removed.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("invalid command format, should be: 'gobgp/delete-server name'")
			}
			if gobgpServer, found := cmdCtx.GetServer(args[0]); found {
				gobgpServer.Stop()
				cmdCtx.DeleteServer(args[0])
				s.Logf("Stopped GoBGP server: %s\n", args[0])
			} else {
				return nil, fmt.Errorf("GoBGP Server with name: %s not found", args[0])
			}
			return nil, nil
		},
	)
}

func GoBGPReloadServerCmd(cmdCtx *GoBGPCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Reload the configuration of a running GoBGP server instance",
			Args:    "name config-file",
			Detail: []string{
				"Apply a new GoBGP configuration file to an already-running server instance, the same way",
				"gobgpd applies a config file change on SIGHUP: the new file is diffed against the last",
				"configuration applied to this server, and peers/peer-groups/route-policies are added,",
				"removed or updated to match.",
				"",
				"Global/listen parameters (ASN, listen address, port) in the new file are ignored - GoBGP",
				"cannot change those on a running server. To change them, use gobgp/delete-server followed",
				"by gobgp/add-server instead.",
				"",
				"Like gobgpd's own reload, per-item failures (e.g. a malformed peer) are only logged, not",
				"returned as a command error - inspect gobgp/peers, gobgp/routes, etc. afterwards to confirm",
				"the change actually applied.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 2 {
				return nil, fmt.Errorf("invalid command format, should be: 'gobgp/reload-server name config-file'")
			}
			state, found := cmdCtx.servers[args[0]]
			if !found {
				return nil, fmt.Errorf("GoBGP Server with name: %s not found", args[0])
			}

			path := s.Path(args[1])
			newConfig, err := gobgpconfig.ReadConfigFile(path, "")
			if err != nil {
				return nil, fmt.Errorf("could not read GoBGP config file %s: %w", args[1], err)
			}

			appliedConfig, err := gobgpconfig.UpdateConfig(s.Context(), state.server, state.config, newConfig)
			if err != nil {
				return nil, fmt.Errorf("error reloading GoBGP server %s: %w", args[0], err)
			}
			state.config = appliedConfig

			s.Logf("Reloaded GoBGP Server %q\n", args[0])

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
				fs.StringP(serverNameFlag, serverNameFlagShort, "", "Name of the GoBGP server instance. Can be omitted if only one instance is active.")
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
			cb := func(p *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
				if p.Type == apiutil.PEER_EVENT_STATE {
					if p.Peer.State.SessionState.String() == "BGP_FSM_"+args[1] {
						if p.Peer.Conf.NeighborAddress.String() == args[0] {
							doneCh <- struct{}{}
						}
					}
				}
			}
			err = gobgpServer.WatchEvent(ctx,
				server.WatchEventMessageCallbacks{
					OnPeerUpdate: cb,
				},
				server.WatchPeer(),
			)
			if err != nil {
				return nil, err
			}
			// check if the peer isn't already in the expected state
			done := false
			err = gobgpServer.ListPeer(s.Context(), &gobgpapi.ListPeerRequest{Address: args[0]}, func(p *gobgpapi.Peer) {
				if p.State.SessionState == stringToSessionState(args[1]) {
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
				fs.StringP(serverNameFlag, serverNameFlagShort, "", "Name of the GoBGP server instance. Can be omitted if only one instance is active.")
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
				fs.StringP(serverNameFlag, serverNameFlagShort, "", "Name of the GoBGP server instance. Can be omitted if only one instance is active.")
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

				family := &types.Family{
					Afi:  types.AfiIPv4,
					Safi: types.SafiUnicast,
				}
				if len(args) > 0 && args[0] != "" {
					family.Afi = types.ParseAfi(args[0])
				}
				if len(args) > 1 && args[1] != "" {
					family.Safi = types.ParseSafi(args[1])
				}
				req := apiutil.ListPathRequest{
					TableType: gobgpapi.TableType_TABLE_TYPE_GLOBAL,
					Family:    bgp.NewFamily(uint16(family.Afi), uint8(family.Safi)),
				}
				var paths []*apiutil.Path
				err = gobgpServer.ListPath(req, func(_ bgp.NLRI, p []*apiutil.Path) {
					paths = append(paths, p...)
				})
				sort.Slice(paths, func(i, j int) bool {
					return paths[i].Nlri.String() < paths[j].Nlri.String()
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

func GoBGPAdvertiseRouteCmd(cmdCtx *GoBGPCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Advertise route on the GoBGP server",
			Args:    "<prefix>",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP(serverNameFlag, serverNameFlagShort, "", "Name of the GoBGP server instance. Can be omitted if only one instance is active.")
			},
		},
		func(s *script.State, args ...string) (waitFunc script.WaitFunc, err error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("invalid command format, should be: 'gobgp/advertise-route <prefix>'")
			}

			prefix, err := netip.ParsePrefix(args[0])
			if err != nil {
				return nil, fmt.Errorf("could not parse prefix: %w", err)
			}

			gobgpServer, err := getGoBGPServer(s, cmdCtx)
			if err != nil {
				return nil, err
			}

			return func(s *script.State) (stdout, stderr string, err error) {
				agentPath, err := types.NewPathForPrefix(prefix)
				if err != nil {
					return "", "", fmt.Errorf("could not create path for prefix %s: %w", prefix, err)
				}
				path, err := gobgp.ToGoBGPPath(agentPath)
				if err != nil {
					return "", "", fmt.Errorf("could not convert path: %w", err)
				}

				_, err = gobgpServer.AddPath(apiutil.AddPathRequest{
					Paths: []*apiutil.Path{path},
				})

				return "", "", err
			}, nil
		},
	)
}

func getGoBGPServer(s *script.State, ctx *GoBGPCmdContext) (*server.BgpServer, error) {
	if len(ctx.servers) == 0 {
		return nil, fmt.Errorf("no GoBGP servers configured")
	}
	name, err := s.Flags.GetString(serverNameFlag)
	if err != nil {
		return nil, fmt.Errorf("could not parse %s: %w", serverNameFlag, err)
	}
	if name == "" && ctx.NServers() > 1 {
		return nil, fmt.Errorf("multiple GoBGP servers are active, %s flag is required", serverNameFlag)
	}
	srv, found := ctx.GetServer(name)
	if !found {
		return nil, fmt.Errorf("GoBGP server with name '%s' not found", name)
	}
	return srv, nil
}

func printPeerHeader(w *tabwriter.Writer) {
	fmt.Fprintln(w, "PeerAddress\tRouterID\tPeerASN\tSessionState\tKeepAlive\tHoldTime\tGracefulRestartTime")
}

func printPeer(w *tabwriter.Writer, peer *gobgpapi.Peer) {
	fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%d\t%d\t%d\n", peer.Conf.NeighborAddress, peer.State.RouterId, peer.State.PeerAsn, sessionStateToString(peer.State.SessionState),
		peer.Timers.State.KeepaliveInterval, peer.Timers.State.NegotiatedHoldTime, peer.GracefulRestart.PeerRestartTime)
}

func printPathHeader(w *tabwriter.Writer) {
	fmt.Fprintln(w, "Prefix\tNextHop\tAttrs")
}

func printPath(w *tabwriter.Writer, path *apiutil.Path) {
	agentPath, err := gobgp.ToAgentPath(path)
	if err != nil {
		fmt.Fprintf(w, "%s\t%s\t%s\n", path.Nlri.String(), "<error>", err)
		return
	}
	fmt.Fprintf(w, "%s\t%s\t%s\n", path.Nlri.String(), api.NextHopFromPathAttributes(agentPath.PathAttributes), agentPath.PathAttributes)
}

func stringToSessionState(stateStr string) gobgpapi.PeerState_SessionState {
	state, ok := gobgpapi.PeerState_SessionState_value[gobgpSessionStatePrefix+stateStr]
	if !ok {
		return gobgpapi.PeerState_SESSION_STATE_UNSPECIFIED
	}
	return gobgpapi.PeerState_SessionState(state)
}

func sessionStateToString(state gobgpapi.PeerState_SessionState) string {
	return strings.TrimPrefix(state.String(), gobgpSessionStatePrefix)
}
