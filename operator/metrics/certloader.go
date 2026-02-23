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
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/promise"
)

const (
	// OperatorPrometheusEnableTLS enable TLS for prometheus server
	OperatorPrometheusEnableTLS = "operator-prometheus-enable-tls"

	// OperatorPrometheusTLSCertFile specifies path to TLS certificate file
	// for prometheus server. The file must contain PEM encoded data.
	OperatorPrometheusTLSCertFile = "operator-prometheus-tls-cert-file"

	// OperatorPrometheusTLSKeyFile specifies path to TLS private key file
	// for prometheus server. The file must contain PEM encoded data.
	OperatorPrometheusTLSKeyFile = "operator-prometheus-tls-key-file"

	// OperatorPrometheusTLSClientCAFiles specifies path to one or more TLS client CA certificates files
	// to use for TLS with mutual authentication (mTLS) for prometheus server.
	// The files must contain PEM encoded data.
	// When provided, this option effectively enables mTLS.
	OperatorPrometheusTLSClientCAFiles = "operator-prometheus-tls-client-ca-files"
)

type prometheusTLSConfigPromise promise.Promise[*certloader.WatchedServerConfig]

// CertloaderGroup provides a promise that can be used to obtain a TLS config
// capable of automatically sourcing/reloading certificates from disk.
//
// We wrap the promise in our own type to avoid conflicts/replacements with other
// certloader promises. We use a group instead of a module to be able to use
// cell.ProvidePrivate and avoid providing the promise to the rest of the hive.
var certloaderGroup = cell.Group(
	cell.ProvidePrivate(func(lc cell.Lifecycle, jobGroup job.Group, log *slog.Logger, cfg certloaderConfig) (prometheusTLSConfigPromise, error) {
		return certloader.NewWatchedServerConfigPromise(lc, jobGroup, log, certloader.Config(cfg))
	}),
	cell.ProvidePrivate(configTls),
	cell.Config(defaultCertloaderConfig),
)

type certloaderConfig struct {
	TLS              bool     `mapstructure:"operator-prometheus-enable-tls"`
	TLSCertFile      string   `mapstructure:"operator-prometheus-tls-cert-file"`
	TLSKeyFile       string   `mapstructure:"operator-prometheus-tls-key-file"`
	TLSClientCAFiles []string `mapstructure:"operator-prometheus-tls-client-ca-files"`
}

var defaultCertloaderConfig = certloaderConfig{
	TLS:              false,
	TLSCertFile:      "",
	TLSKeyFile:       "",
	TLSClientCAFiles: []string{},
}

func (def certloaderConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(OperatorPrometheusEnableTLS, def.TLS, "Enable TLS for prometheus server")
	flags.String(OperatorPrometheusTLSCertFile, def.TLSCertFile, "Path to TLS certificate file for prometheus server. The file must contain PEM encoded data")
	flags.String(OperatorPrometheusTLSKeyFile, def.TLSKeyFile, "Path to TLS private key file for prometheus server. The file must contain PEM encoded data.")
	flags.StringSlice(OperatorPrometheusTLSClientCAFiles, def.TLSClientCAFiles, "Path to one or more TLS client CA certificates files to use for TLS with mutual authentication (mTLS) for prometheus server. The files must contain PEM encoded data. When provided, this option effectively enables mTLS.")
}

func configTls(logger *slog.Logger, cfg certloaderConfig, prometheusTlsConfigPromise prometheusTLSConfigPromise) metrics.TLSConfigPromise {
	if !cfg.TLS {
		logger.Debug("Operator prometheus TLS disabled")
		return nil
	}

	return promise.Map(prometheusTlsConfigPromise, func(certLoaderWatchedServerConfig *certloader.WatchedServerConfig) *tls.Config {
		return certLoaderWatchedServerConfig.ServerConfig(&tls.Config{
			MinVersion: tls.VersionTLS13,
		})
	})
}
