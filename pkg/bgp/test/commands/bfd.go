// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/pkg/bgp/testutils"
)

const bfdWaitTimeout = 8 * time.Second

// BFDPeerCmdContext tracks test BFD peers created by a script.
type BFDPeerCmdContext struct {
	peers map[string]*testutils.BFDPeer
}

func NewBFDPeerCmdContext() *BFDPeerCmdContext {
	return &BFDPeerCmdContext{peers: make(map[string]*testutils.BFDPeer)}
}

func (ctx *BFDPeerCmdContext) Cleanup() {
	for name, peer := range ctx.peers {
		peer.Stop()
		delete(ctx.peers, name)
	}
}

func BFDPeerScriptCmds(ctx *BFDPeerCmdContext, tb testing.TB) map[string]script.Cmd {
	return map[string]script.Cmd{
		"bfd/add-peer":   bfdAddPeerCmd(ctx, tb),
		"bfd/responding": bfdRespondingCmd(ctx),
		"bfd/wait-up":    bfdWaitUpCmd(ctx),
	}
}

func bfdAddPeerCmd(ctx *BFDPeerCmdContext, tb testing.TB) script.Cmd {
	return script.Command(
		script.CmdUsage{Summary: "Add a BFD test peer", Args: "name address"},
		func(_ *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, script.ErrUsage
			}
			if _, exists := ctx.peers[args[0]]; exists {
				return nil, fmt.Errorf("BFD peer %q already exists", args[0])
			}
			ctx.peers[args[0]] = testutils.NewBFDPeer(tb, args[1])
			return nil, nil
		},
	)
}

func bfdRespondingCmd(ctx *BFDPeerCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{Summary: "Set whether a BFD test peer responds", Args: "name true|false"},
		func(_ *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, script.ErrUsage
			}
			peer, exists := ctx.peers[args[0]]
			if !exists {
				return nil, fmt.Errorf("BFD peer %q not found", args[0])
			}
			responding, err := strconv.ParseBool(args[1])
			if err != nil {
				return nil, fmt.Errorf("invalid responding value %q: %w", args[1], err)
			}
			peer.SetResponding(responding)
			return nil, nil
		},
	)
}

func bfdWaitUpCmd(ctx *BFDPeerCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{Summary: "Wait for a BFD test peer to observe an up session", Args: "name"},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}
			peer, exists := ctx.peers[args[0]]
			if !exists {
				return nil, fmt.Errorf("BFD peer %q not found", args[0])
			}
			deadline := time.NewTimer(bfdWaitTimeout)
			ticker := time.NewTicker(25 * time.Millisecond)
			return func(_ *script.State) (string, string, error) {
				defer deadline.Stop()
				defer ticker.Stop()
				for {
					if peer.SawUp() {
						return "", "", nil
					}
					select {
					case <-s.Context().Done():
						return "", "", s.Context().Err()
					case <-deadline.C:
						return "", "", fmt.Errorf("timed out waiting for BFD peer %q to come up", args[0])
					case <-ticker.C:
					}
				}
			}, nil
		},
	)
}
