// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package hubblecell

import (
	"github.com/cilium/hive/cell"
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
	cell.ProvidePrivate(func(cfg certloaderConfig) certloader.Config {
		return certloader.Config{
			TLS:              !cfg.DisableServerTLS,
			TLSCertFile:      cfg.TLSCertFile,
			TLSKeyFile:       cfg.TLSKeyFile,
			TLSClientCAFiles: cfg.TLSClientCAFiles,
		}
	}),
	cell.ProvidePrivate(certloader.NewWatchedServerConfigPromise),
	cell.ProvidePrivate(func(p promise.Promise[*certloader.WatchedServerConfig]) tlsConfigPromise {
		return p
	}),
	cell.Config(defaultCertloaderConfig),
)

type certloaderConfig struct {
	DisableServerTLS bool     `mapstructure:"hubble-disable-tls"`
	TLSCertFile      string   `mapstructure:"hubble-tls-cert-file"`
	TLSKeyFile       string   `mapstructure:"hubble-tls-key-file"`
	TLSClientCAFiles []string `mapstructure:"hubble-tls-client-ca-files"`
}

var defaultCertloaderConfig = certloaderConfig{
	DisableServerTLS: true,
	TLSCertFile:      "",
	TLSKeyFile:       "",
	TLSClientCAFiles: []string{},
}

func (def certloaderConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("hubble-disable-tls", def.DisableServerTLS, "Allow Hubble server to run on the given listen address without TLS.")
	flags.String("hubble-tls-cert-file", def.TLSCertFile, "Path to the public key file for the Hubble server. The file must contain PEM encoded data.")
	flags.String("hubble-tls-key-file", def.TLSKeyFile, "Path to the private key file for the Hubble server. The file must contain PEM encoded data.")
	flags.StringSlice("hubble-tls-client-ca-files", def.TLSClientCAFiles, "Paths to one or more public key files of client CA certificates to use for TLS with mutual authentication (mTLS). The files must contain PEM encoded data. When provided, this option effectively enables mTLS.")
}
