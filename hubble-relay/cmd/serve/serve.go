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

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/hubble/relay/defaults"
	"github.com/cilium/cilium/pkg/hubble/relay/server"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/pprof"

	"github.com/google/gops/agent"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
)

const (
	keyPprof                  = "pprof"
	keyPprofPort              = "pprof-port"
	keyGops                   = "gops"
	keyGopsPort               = "gops-port"
	keyDialTimeout            = "dial-timeout"
	keyRetryTimeout           = "retry-timeout"
	keyListenAddress          = "listen-address"
	keyPeerService            = "peer-service"
	keySortBufferMaxLen       = "sort-buffer-len-max"
	keySortBufferDrainTimeout = "sort-buffer-drain-timeout"
	keyTLSClientCertFile      = "tls-client-cert-file"
	keyTLSClientKeyFile       = "tls-client-key-file"
	keyTLSHubbleServerCAFiles = "tls-hubble-server-ca-files"
	keyTLSClientDisabled      = "disable-client-tls"
	keyTLSServerCertFile      = "tls-server-cert-file"
	keyTLSServerKeyFile       = "tls-server-key-file"
	keyTLSServerDisabled      = "disable-server-tls"
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
	flags.Bool(
		keyPprof, false, "Enable serving the pprof debugging API",
	)
	flags.Int(
		keyPprofPort, defaults.PprofPort, "Port that the pprof listens on",
	)
	flags.Bool(
		keyGops, true, "Run gops agent",
	)
	flags.Int(
		keyGopsPort,
		defaults.GopsPort,
		"Port for gops server to listen on")
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
	flags.String(
		keyTLSClientCertFile,
		"",
		"Path to the public key file for the client certificate to connect to Hubble server instances. The file must contain PEM encoded data.",
	)
	flags.String(
		keyTLSClientKeyFile,
		"",
		"Path to the private key file for the client certificate to connect to Hubble server instances. The file must contain PEM encoded data.",
	)
	flags.StringSlice(
		keyTLSHubbleServerCAFiles,
		[]string{},
		"Paths to one or more public key files of the CA which sign certificates for Hubble server instances.",
	)
	flags.String(
		keyTLSServerCertFile,
		"",
		"Path to the public key file for the Hubble Relay server. The file must contain PEM encoded data.",
	)
	flags.String(
		keyTLSServerKeyFile,
		"",
		"Path to the private key file for the Hubble Relay server. The file must contain PEM encoded data.",
	)
	flags.Bool(
		keyTLSClientDisabled,
		false,
		"Disable (m)TLS and allow the connection to Hubble server instances to be over plaintext.",
	)
	flags.Bool(
		keyTLSServerDisabled,
		false,
		"Disable TLS for the server and allow clients to connect over plaintext.",
	)
	vp.BindPFlags(flags)

	return cmd
}

func runServe(vp *viper.Viper) error {
	logging.ConfigureLogLevel(vp.GetBool("debug"))
	logger := logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-relay")

	opts := []server.Option{
		server.WithDialTimeout(vp.GetDuration(keyDialTimeout)),
		server.WithHubbleTarget(vp.GetString(keyPeerService)),
		server.WithListenAddress(vp.GetString(keyListenAddress)),
		server.WithRetryTimeout(vp.GetDuration(keyRetryTimeout)),
		server.WithSortBufferMaxLen(vp.GetInt(keySortBufferMaxLen)),
		server.WithSortBufferDrainTimeout(vp.GetDuration(keySortBufferDrainTimeout)),
		server.WithLogger(logger),
	}

	// Relay to Hubble TLS/mTLS setup.
	var tlsClientConfig *certloader.WatchedClientConfig
	if vp.GetBool(keyTLSClientDisabled) {
		opts = append(opts, server.WithInsecureClient())
	} else {
		tlsClientConfig, err := certloader.NewWatchedClientConfig(
			logger.WithField("config", "tls-to-hubble"),
			vp.GetStringSlice(keyTLSHubbleServerCAFiles),
			vp.GetString(keyTLSClientCertFile),
			vp.GetString(keyTLSClientKeyFile),
		)
		if err != nil {
			return err
		}
		opts = append(opts, server.WithClientTLS(tlsClientConfig))
	}

	// Clients to Relay TLS setup.
	var tlsServerConfig *certloader.WatchedServerConfig
	if vp.GetBool(keyTLSServerDisabled) {
		opts = append(opts, server.WithInsecureServer())
	} else {
		tlsServerConfig, err := certloader.NewWatchedServerConfig(
			logger.WithField("config", "tls-server"),
			nil, // no caFiles, mTLS is not supported for Relay clients yet.
			vp.GetString(keyTLSServerCertFile),
			vp.GetString(keyTLSServerKeyFile),
		)
		if err != nil {
			return err
		}
		opts = append(opts, server.WithServerTLS(tlsServerConfig))
	}

	if vp.GetBool(keyPprof) {
		pprof.Enable(vp.GetInt(keyPprofPort))
	}
	gopsEnabled := vp.GetBool(keyGops)
	if gopsEnabled {
		addr := fmt.Sprintf("127.0.0.1:%d", vp.GetInt(keyGopsPort))
		if err := agent.Listen(agent.Options{
			Addr:                   addr,
			ReuseSocketAddrAndPort: true,
		}); err != nil {
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
		if tlsServerConfig != nil {
			tlsServerConfig.Stop()
		}
		if tlsClientConfig != nil {
			tlsClientConfig.Stop()
		}
		if gopsEnabled {
			agent.Close()
		}
	}()
	return srv.Serve()
}
