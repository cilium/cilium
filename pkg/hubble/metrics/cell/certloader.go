// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metricscell

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/promise"
)

type tlsConfigPromise promise.Promise[*certloader.WatchedServerConfig]

// certloaderGroup provides a promise that can be used to obtain a TLS config
// capable of automatically sourcing/reloading certificates from disk.
//
// We wrap the promise in our own type to avoid conflicts/replacements with other
// certloader promises. We use a group instead of a module to be able to use
// cell.ProvidePrivate and avoid providing the promise to the rest of the hive.
var certloaderGroup = cell.Group(
	cell.ProvidePrivate(func(lc cell.Lifecycle, jobGroup job.Group, log *slog.Logger, cfg certloaderConfig) (tlsConfigPromise, error) {
		return certloader.NewWatchedServerConfigPromise(lc, jobGroup, log, certloader.Config(cfg))
	}),
	cell.Config(defaultCertloaderConfig),
)

type certloaderConfig struct {
	TLS              bool     `mapstructure:"hubble-metrics-server-enable-tls"`
	TLSCertFile      string   `mapstructure:"hubble-metrics-server-tls-cert-file"`
	TLSKeyFile       string   `mapstructure:"hubble-metrics-server-tls-key-file"`
	TLSClientCAFiles []string `mapstructure:"hubble-metrics-server-tls-client-ca-files"`
}

var defaultCertloaderConfig = certloaderConfig{
	TLS:              false,
	TLSCertFile:      "",
	TLSKeyFile:       "",
	TLSClientCAFiles: []string{},
}

func (def certloaderConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("hubble-metrics-server-enable-tls", def.TLS, "Run the Hubble metrics server on the given listen address with TLS.")
	flags.String("hubble-metrics-server-tls-cert-file", def.TLSCertFile, "Path to the public key file for the Hubble metrics server. The file must contain PEM encoded data.")
	flags.String("hubble-metrics-server-tls-key-file", def.TLSKeyFile, "Path to the private key file for the Hubble metrics server. The file must contain PEM encoded data.")
	flags.StringSlice("hubble-metrics-server-tls-client-ca-files", def.TLSClientCAFiles, "Paths to one or more public key files of client CA certificates to use for TLS with mutual authentication (mTLS). The files must contain PEM encoded data. When provided, this option effectively enables mTLS.")
}
