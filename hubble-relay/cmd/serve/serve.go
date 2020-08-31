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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
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
	opts := []server.Option{
		server.WithDialTimeout(vp.GetDuration(keyDialTimeout)),
		server.WithHubbleTarget(vp.GetString(keyPeerService)),
		server.WithListenAddress(vp.GetString(keyListenAddress)),
		server.WithRetryTimeout(vp.GetDuration(keyRetryTimeout)),
		server.WithSortBufferMaxLen(vp.GetInt(keySortBufferMaxLen)),
		server.WithSortBufferDrainTimeout(vp.GetDuration(keySortBufferDrainTimeout)),
	}
	clientTLSOption, err := buildClientTLSOption(vp)
	if err != nil {
		return err
	}
	opts = append(opts, clientTLSOption)

	serverTLSOption, err := buildServerTLSOption(vp)
	if err != nil {
		return err
	}
	opts = append(opts, serverTLSOption)

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

func buildClientTLSOption(vp *viper.Viper) (server.Option, error) {
	if vp.GetBool(keyTLSClientDisabled) {
		return server.WithInsecureClient(), nil
	}

	var tlsHubbleServerCAs *x509.CertPool
	tlsHubbleServerCAPaths := vp.GetStringSlice(keyTLSHubbleServerCAFiles)
	switch {
	case len(tlsHubbleServerCAPaths) > 0:
		tlsHubbleServerCAs = x509.NewCertPool()
		for _, path := range tlsHubbleServerCAPaths {
			certPEM, err := ioutil.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("cannot load cert '%s': %s", path, err)
			}
			if ok := tlsHubbleServerCAs.AppendCertsFromPEM(certPEM); !ok {
				return nil, fmt.Errorf("cannot process cert '%s': must be a PEM encoded certificate", path)
			}
		}
	default:
		var err error
		tlsHubbleServerCAs, err = x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
	}

	tlsClientCertPath := vp.GetString(keyTLSClientCertFile)
	tlsClientKeyPath := vp.GetString(keyTLSClientKeyFile)
	switch {
	case tlsClientCertPath != "" && tlsClientKeyPath != "": // mTLS
		cert, err := tls.LoadX509KeyPair(tlsClientCertPath, tlsClientKeyPath)
		if err != nil {
			return nil, err
		}
		return server.WithClientMTLSFromCert(tlsHubbleServerCAs, cert), nil
	case tlsClientCertPath == "" && tlsClientKeyPath == "": // TLS
		return server.WithClientTLSFromCert(tlsHubbleServerCAs), nil
	default: // invalid parameters
		return nil, fmt.Errorf(
			"both or none of '%s' and '%s' must be provided; have %s=%s, %s=%s",
			keyTLSClientCertFile, keyTLSClientKeyFile,
			keyTLSClientCertFile, tlsClientCertPath,
			keyTLSClientKeyFile, tlsClientKeyPath,
		)
	}
}

func buildServerTLSOption(vp *viper.Viper) (server.Option, error) {
	if vp.GetBool(keyTLSServerDisabled) {
		return server.WithInsecureServer(), nil
	}

	tlsServerCertPath := vp.GetString(keyTLSServerCertFile)
	if tlsServerCertPath == "" {
		return nil, errors.New("no TLS certificate provided for the server")
	}
	tlsServerKeyPath := vp.GetString(keyTLSServerKeyFile)
	if tlsServerKeyPath == "" {
		return nil, errors.New("no TLS key provided for the server")
	}
	cert, err := tls.LoadX509KeyPair(tlsServerCertPath, tlsServerKeyPath)
	if err != nil {
		return nil, err
	}
	return server.WithTLSFromCert(cert), nil
}
