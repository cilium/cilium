// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package serve

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/cilium/pkg/hubble/relay/defaults"
	"github.com/cilium/cilium/pkg/hubble/relay/server"
	"github.com/cilium/cilium/pkg/pprof"

	"github.com/google/gops/agent"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

type flags struct {
	debug                  bool
	pprof                  bool
	gops                   bool
	dialTimeout            time.Duration
	listenAddress          string
	peerService            string
	retryTimeout           time.Duration
	sortBufferMaxLen       int
	sortBufferDrainTimeout time.Duration
}

// New creates a new serve command.
func New() *cobra.Command {
	var f flags
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the gRPC proxy server",
		Long:  `Run the gRPC proxy server.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runServe(f)
		},
	}
	cmd.Flags().BoolVarP(
		&f.debug, "debug", "D", false, "Run in debug mode",
	)
	cmd.Flags().BoolVar(
		&f.pprof, "pprof", false, "Enable serving the pprof debugging API",
	)
	cmd.Flags().BoolVar(
		&f.gops, "gops", true, "Run gops agent",
	)
	cmd.Flags().DurationVar(
		&f.dialTimeout, "dial-timeout",
		defaults.DialTimeout,
		"Dial timeout when connecting to hubble peers")
	cmd.Flags().DurationVar(
		&f.retryTimeout, "retry-timeout",
		defaults.RetryTimeout,
		"Time to wait before attempting to reconnect to a hubble peer when the connection is lost")
	cmd.Flags().StringVar(
		&f.listenAddress, "listen-address",
		defaults.ListenAddress,
		"Address on which to listen")
	cmd.Flags().StringVar(
		&f.peerService, "peer-service",
		defaults.HubbleTarget,
		"Address of the server that implements the peer gRPC service")
	cmd.Flags().IntVar(
		&f.sortBufferMaxLen, "sort-buffer-len-max",
		defaults.SortBufferMaxLen,
		"Max number of flows that can be buffered for sorting before being sent to the client (per request)")
	cmd.Flags().DurationVar(
		&f.sortBufferDrainTimeout, "sort-buffer-drain-timeout",
		defaults.SortBufferDrainTimeout,
		"When the per-request flows sort buffer is not full, a flow is drained every time this timeout is reached (only affects requests in follow-mode)")
	return cmd
}

func runServe(f flags) error {
	opts := []server.Option{
		server.WithDialTimeout(f.dialTimeout),
		server.WithHubbleTarget(f.peerService),
		server.WithListenAddress(f.listenAddress),
		server.WithRetryTimeout(f.retryTimeout),
		server.WithSortBufferMaxLen(f.sortBufferMaxLen),
		server.WithSortBufferDrainTimeout(f.sortBufferDrainTimeout),
		server.WithInsecure(), //FIXME: add option to set server and client TLS settings
	}
	if f.debug {
		opts = append(opts, server.WithDebug())
	}
	if f.pprof {
		pprof.Enable()
	}
	if f.gops {
		if err := agent.Listen(agent.Options{}); err != nil {
			return fmt.Errorf("failed to start gops agent: %v", err)
		}
	}
	srv, err := server.New(opts...)
	if err != nil {
		return fmt.Errorf("cannot create hubble-relay server: %v", err)
	}
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)
		<-sigs
		srv.Stop()
		if f.gops {
			agent.Close()
		}
	}()
	return srv.Serve()
}
