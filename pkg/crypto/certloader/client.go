// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certloader

import (
	"crypto/tls"
	"fmt"

	"github.com/sirupsen/logrus"
)

// ClientConfigBuilder creates tls.Config to be used as TLS client.
type ClientConfigBuilder interface {
	IsMutualTLS() bool
	ClientConfig(base *tls.Config) *tls.Config
}

// WatchedClientConfig is a ClientConfigBuilder backed up by files to be
// watched for changes.
type WatchedClientConfig struct {
	*Watcher
	log logrus.FieldLogger
}

// NewWatchedClientConfig returns a WatchedClientConfig configured with the
// provided files. When caFiles is nil or empty, the system CA CertPool is
// used. To configure a mTLS capable ClientConfigBuilder, both certFile and
// privkeyFile must be provided.
func NewWatchedClientConfig(log logrus.FieldLogger, caFiles []string, certFile, privkeyFile string) (*WatchedClientConfig, error) {
	w, err := NewWatcher(log, caFiles, certFile, privkeyFile)
	if err != nil {
		return nil, err
	}
	c := &WatchedClientConfig{
		Watcher: w,
		log:     log,
	}
	return c, nil
}

// IsMutualTLS implement ClientConfigBuilder.
func (c *WatchedClientConfig) IsMutualTLS() bool {
	return c.HasKeypair()
}

// ClientConfig implement ClientConfigBuilder.
func (c *WatchedClientConfig) ClientConfig(base *tls.Config) *tls.Config {
	// get both the keypair and CAs at once even if keypair may be used only
	// later, in order to get a "consistent view" of the configuration as it
	// may change between now and the call to GetClientCertificate.
	keypair, caCertPool := c.KeypairAndCACertPool()
	tlsConfig := base.Clone()
	tlsConfig.RootCAs = caCertPool
	tlsConfig.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if !c.IsMutualTLS() {
			return nil, fmt.Errorf("mTLS client certificate requested, but not configured")
		}
		c.log.WithField("keypair-sn", keypairId(keypair)).Debugf("Client mtls handshake")
		return keypair, nil
	}

	return tlsConfig
}
