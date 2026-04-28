// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"crypto/tls"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/promise"
)

const (
	// PrometheusEnableTLS enables TLS for the agent prometheus metrics server.
	PrometheusEnableTLS = "prometheus-enable-tls"
	// PrometheusTLSCertFile is the path to the certificate PEM file.
	PrometheusTLSCertFile = "prometheus-tls-cert-file"
	// PrometheusTLSKeyFile is the path to the private key PEM file.
	PrometheusTLSKeyFile = "prometheus-tls-key-file"
	// PrometheusTLSClientCAFiles are paths to client CA certificates for mTLS.
	PrometheusTLSClientCAFiles = "prometheus-tls-client-ca-files"
)

type agentPrometheusTLSConfigPromise promise.Promise[*certloader.WatchedServerConfig]

// certloaderGroup provides a promise that can be used to obtain a TLS config
// capable of automatically sourcing/reloading certificates from disk.
//
// We wrap the promise in our own type to avoid conflicts/replacements with other
// certloader promises. We use a group instead of a module to be able to use
// cell.ProvidePrivate and avoid providing the promise to the rest of the hive.
var certloaderGroup = cell.Group(
	cell.ProvidePrivate(func(lc cell.Lifecycle, jobGroup job.Group, log *slog.Logger, cfg certloaderConfig) (agentPrometheusTLSConfigPromise, error) {
		return certloader.NewWatchedServerConfigPromise(lc, jobGroup, log, certloader.Config(cfg))
	}),
	cell.ProvidePrivate(configAgentMetricsTLS),
	cell.Config(defaultCertloaderConfig),
)

type certloaderConfig struct {
	TLS              bool     `mapstructure:"prometheus-enable-tls"`
	TLSCertFile      string   `mapstructure:"prometheus-tls-cert-file"`
	TLSKeyFile       string   `mapstructure:"prometheus-tls-key-file"`
	TLSClientCAFiles []string `mapstructure:"prometheus-tls-client-ca-files"`
}

var defaultCertloaderConfig = certloaderConfig{
	TLS:              false,
	TLSCertFile:      "",
	TLSKeyFile:       "",
	TLSClientCAFiles: []string{},
}

func (def certloaderConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(PrometheusEnableTLS, def.TLS, "Run the agent prometheus metrics server with TLS.")
	flags.String(PrometheusTLSCertFile, def.TLSCertFile, "Path to the public key file for the agent prometheus metrics server. The file must contain PEM encoded data.")
	flags.String(PrometheusTLSKeyFile, def.TLSKeyFile, "Path to the private key file for the agent prometheus metrics server. The file must contain PEM encoded data.")
	flags.StringSlice(PrometheusTLSClientCAFiles, def.TLSClientCAFiles, "Paths to one or more public key files of client CA certificates to use for TLS with mutual authentication (mTLS). The files must contain PEM encoded data. When provided, this option effectively enables mTLS.")
}

func configAgentMetricsTLS(logger *slog.Logger, cfg certloaderConfig, tlsPromise agentPrometheusTLSConfigPromise) TLSConfigPromise {
	if !cfg.TLS {
		logger.Debug("Agent prometheus metrics TLS disabled")
		return nil
	}
	return promise.Map(tlsPromise, func(wsc *certloader.WatchedServerConfig) *tls.Config {
		return wsc.ServerConfig(&tls.Config{
			MinVersion: tls.VersionTLS13,
		})
	})
}
