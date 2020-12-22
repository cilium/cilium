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
