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

	"github.com/cilium/cilium/pkg/hubble/relay/defaults"
	"github.com/cilium/cilium/pkg/hubble/relay/server"
	"github.com/cilium/cilium/pkg/pprof"

	"github.com/google/gops/agent"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
)

const (
	keyDebug                  = "debug"
	keyPprof                  = "pprof"
	keyGops                   = "gops"
	keyDialTimeout            = "dial-timeout"
	keyRetryTimeout           = "retry-timeout"
	keyListenAddress          = "listen-address"
	keyPeerService            = "peer-service"
	keySortBufferMaxLen       = "sort-buffer-len-max"
	keySortBufferDrainTimeout = "sort-buffer-drain-timeout"
)

// New creates a new serve command.
func New(vp *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the gRPC proxy server",
		Long:  `Run the gRPC proxy server.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runServe(vp)
		},
	}
	flags := cmd.Flags()
	flags.BoolP(
		keyDebug, "D", false, "Run in debug mode",
	)
	flags.Bool(
		keyPprof, false, "Enable serving the pprof debugging API",
	)
	flags.Bool(
		keyGops, true, "Run gops agent",
	)
	flags.Duration(
		keyDialTimeout,
		defaults.DialTimeout,
		"Dial timeout when connecting to hubble peers")
	flags.Duration(
		keyRetryTimeout,
		defaults.RetryTimeout,
		"Time to wait before attempting to reconnect to a hubble peer when the connection is lost")
	flags.String(
		keyListenAddress,
		defaults.ListenAddress,
		"Address on which to listen")
	flags.String(
		keyPeerService,
		defaults.HubbleTarget,
		"Address of the server that implements the peer gRPC service")
	flags.Int(
		keySortBufferMaxLen,
		defaults.SortBufferMaxLen,
		"Max number of flows that can be buffered for sorting before being sent to the client (per request)")
	flags.Duration(
		keySortBufferDrainTimeout,
		defaults.SortBufferDrainTimeout,
		"When the per-request flows sort buffer is not full, a flow is drained every time this timeout is reached (only affects requests in follow-mode)")
	vp.BindPFlags(flags)

	return cmd
}

func runServe(vp *viper.Viper) error {
	opts := []server.Option{
		server.WithDialTimeout(vp.GetDuration(keyDialTimeout)),
		server.WithHubbleTarget(vp.GetString(keyPeerService)),
		server.WithListenAddress(vp.GetString(keyListenAddress)),
		server.WithRetryTimeout(vp.GetDuration(keyRetryTimeout)),
		server.WithSortBufferMaxLen(vp.GetInt(keySortBufferMaxLen)),
		server.WithSortBufferDrainTimeout(vp.GetDuration(keySortBufferDrainTimeout)),
		server.WithInsecure(), //FIXME: add option to set server and client TLS settings
	}
	if vp.GetBool(keyDebug) {
		opts = append(opts, server.WithDebug())
	}
	if vp.GetBool(keyPprof) {
		pprof.Enable()
	}
	gopsEnabled := vp.GetBool(keyGops)
	if gopsEnabled {
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
		if gopsEnabled {
			agent.Close()
		}
	}()
	return srv.Serve()
}
