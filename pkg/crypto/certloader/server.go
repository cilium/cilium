// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certloader

import (
	"crypto/tls"
	"errors"

	"github.com/sirupsen/logrus"
)

var alpnProtocolH2 = "h2"

// ServerConfigBuilder creates tls.Config to be used as TLS server.
type ServerConfigBuilder interface {
	IsMutualTLS() bool
	ServerConfig(base *tls.Config) *tls.Config
}

// WatchedServerConfig is a ServerConfigBuilder backed up by files to be
// watched for changes. The tls.Config created will use the latest CA and
// keypair on each TLS handshake, allowing for smooth TLS configuration
// rotation.
type WatchedServerConfig struct {
	*Watcher
	log logrus.FieldLogger
}

var (
	// ErrMissingCertFile is returned when the certificate file is missing.
	ErrMissingCertFile = errors.New("certificate file path is required")
	// ErrMissingPrivkeyFile is returned when the private key file is missing.
	ErrMissingPrivkeyFile = errors.New("private key file path is required")
)

// NewWatchedServerConfig returns a WatchedServerConfig configured with the
// provided files. both certFile and privkeyFile must be provided. To configure
// a mTLS capable ServerConfigBuilder, caFiles must contains at least one file
// path.
func NewWatchedServerConfig(log logrus.FieldLogger, caFiles []string, certFile, privkeyFile string) (*WatchedServerConfig, error) {
	if certFile == "" {
		return nil, ErrMissingCertFile
	}
	if privkeyFile == "" {
		return nil, ErrMissingPrivkeyFile
	}
	w, err := NewWatcher(log, caFiles, certFile, privkeyFile)
	if err != nil {
		return nil, err
	}
	c := &WatchedServerConfig{
		Watcher: w,
		log:     log,
	}
	return c, nil
}

// FutureWatchedServerConfig returns a channel where exactly one
// WatchedServerConfig will be sent once the given files are ready and loaded.
// This can be useful when the file paths are well-known, but the files
// themselves don't exist yet. both certFile and privkeyFile must be provided.
// To configure a mTLS capable ServerConfigBuilder, caFiles must contains at
// least one file path.
func FutureWatchedServerConfig(log logrus.FieldLogger, caFiles []string, certFile, privkeyFile string) (<-chan *WatchedServerConfig, error) {
	if certFile == "" {
		return nil, ErrMissingCertFile
	}
	if privkeyFile == "" {
		return nil, ErrMissingPrivkeyFile
	}
	ew, err := FutureWatcher(log, caFiles, certFile, privkeyFile)
	if err != nil {
		return nil, err
	}

	res := make(chan *WatchedServerConfig)
	go func(res chan<- *WatchedServerConfig) {
		defer close(res)
		if watcher, ok := <-ew; ok {
			res <- &WatchedServerConfig{
				Watcher: watcher,
				log:     log,
			}
		}
	}(res)

	return res, nil
}

// IsMutualTLS implement ServerConfigBuilder.
func (c *WatchedServerConfig) IsMutualTLS() bool {
	return c.HasCustomCA()
}

// ServerConfig implement ServerConfigBuilder.
func (c *WatchedServerConfig) ServerConfig(base *tls.Config) *tls.Config {
	// We return a tls.Config having only the GetConfigForClient member set.
	// When a client initialize a TLS handshake, this function will be called
	// and the tls.Config returned by GetConfigForClient will be used. This
	// mechanism allow us to reload the certificates transparently between two
	// clients connections without having to restart the server.
	// See also the discussion at https://github.com/golang/go/issues/16066.
	return &tls.Config{
		GetConfigForClient: func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			keypair, caCertPool := c.KeypairAndCACertPool()
			tlsConfig := base.Clone()
			tlsConfig.Certificates = []tls.Certificate{*keypair}
			tlsConfig.NextProtos = constructWithH2ProtoIfNeed(tlsConfig.NextProtos)
			if c.IsMutualTLS() {
				// We've been configured to serve mTLS, so setup the ClientCAs
				// accordingly.
				tlsConfig.ClientCAs = caCertPool
				// The caller may have its own desire about the handshake
				// ClientAuthType. We honor it unless its tls.NoClientCert (the
				// default zero value) as we are configured to serve mTLS.
				if tlsConfig.ClientAuth == tls.NoClientCert {
					tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
				}
			}
			c.log.WithField("keypair-sn", keypairId(keypair)).
				Debug("Server tls handshake")
			return tlsConfig, nil
		},
		// NOTE: this MinVersion is not used as this tls.Config will be
		// overridden by the one returned by GetConfigForClient. The effective
		// MinVersion must be set by the provided base TLS configuration.
		MinVersion: tls.VersionTLS13,
	}
}

// constructWithH2ProtoIfNeed constructs a new slice of protocols with h2
func constructWithH2ProtoIfNeed(existingProtocols []string) []string {
	for _, p := range existingProtocols {
		if p == alpnProtocolH2 {
			return existingProtocols
		}
	}
	ret := make([]string, 0, len(existingProtocols)+1)
	ret = append(ret, existingProtocols...)
	return append(ret, alpnProtocolH2)
}
