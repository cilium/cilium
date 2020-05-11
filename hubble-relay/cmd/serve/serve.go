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

	"github.com/cilium/cilium/pkg/hubble/relay"
	"github.com/cilium/cilium/pkg/hubble/relay/relayoption"
	"github.com/cilium/cilium/pkg/pprof"

	"github.com/google/gops/agent"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

type flags struct {
	debug         bool
	pprof         bool
	gops          bool
	dialTimeout   time.Duration
	listenAddress string
	peerService   string
	retryTimeout  time.Duration
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
		relayoption.Default.DialTimeout,
		"Dial timeout when connecting to hubble peers")
	cmd.Flags().DurationVar(
		&f.retryTimeout, "retry-timeout",
		relayoption.Default.RetryTimeout,
		"Time to wait before attempting to reconnect to a hubble peer when the connection is lost")
	cmd.Flags().StringVar(
		&f.listenAddress, "listen-address",
		relayoption.Default.ListenAddress,
		"Address on which to listen")
	cmd.Flags().StringVar(
		&f.peerService, "peer-service",
		relayoption.Default.HubbleTarget,
		"Address of the server that implements the peer gRPC service")
	return cmd
}

func runServe(f flags) error {
	opts := []relayoption.Option{
		relayoption.WithDialTimeout(f.dialTimeout),
		relayoption.WithHubbleTarget(f.peerService),
		relayoption.WithListenAddress(f.listenAddress),
		relayoption.WithRetryTimeout(f.retryTimeout),
	}
	if f.debug {
		opts = append(opts, relayoption.WithDebug())
	}
	if f.pprof {
		pprof.Enable()
	}
	if f.gops {
		if err := agent.Listen(agent.Options{}); err != nil {
			return fmt.Errorf("failed to start gops agent: %v", err)
		}
	}
	srv, err := relay.NewServer(opts...)
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
