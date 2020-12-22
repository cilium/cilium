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

// +build !privileged_tests

package certloader

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func TestWatchedClientConfigIsMutualTLS(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)
	logger, _ := test.NewNullLogger()

	tests := []struct {
		name        string
		constructor func() (*WatchedClientConfig, error)
		isMutualTLS bool
	}{
		{
			name: "empty",
			constructor: func() (*WatchedClientConfig, error) {
				return NewWatchedClientConfig(logger, nil, "", "")
			},
			isMutualTLS: false,
		},
		{
			name: "keypair only",
			constructor: func() (*WatchedClientConfig, error) {
				return NewWatchedClientConfig(logger, nil, relay.certFile, relay.privkeyFile)
			},
			isMutualTLS: true,
		},
		{
			name: "CA only",
			constructor: func() (*WatchedClientConfig, error) {
				return NewWatchedClientConfig(logger, hubble.caFiles, "", "")
			},
			isMutualTLS: false,
		},
		{
			name: "CA and keypair",
			constructor: func() (*WatchedClientConfig, error) {
				return NewWatchedClientConfig(logger, hubble.caFiles, relay.certFile, relay.privkeyFile)
			},
			isMutualTLS: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Stop()
			if tt.isMutualTLS {
				assert.True(t, c.IsMutualTLS())
			} else {
				assert.False(t, c.IsMutualTLS())
			}
		})
	}
}

func TestNewWatchedClientConfig(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)
	logger, _ := test.NewNullLogger()

	expectedCaCertPool := x509.NewCertPool()
	if ok := expectedCaCertPool.AppendCertsFromPEM(initialHubbleServerCA); !ok {
		t.Fatal("AppendCertsFromPEM", initialHubbleServerCA)
	}
	expectedKeypair, err := tls.X509KeyPair(initialRelayClientCertificate, initialRelayClientPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	c, err := NewWatchedClientConfig(logger, hubble.caFiles, relay.certFile, relay.privkeyFile)
	assert.Nil(t, err)
	assert.NotNil(t, c)
	defer c.Stop()

	tlsConfig := c.ClientConfig(&tls.Config{
		MinVersion: tls.VersionTLS13,
	})
	assert.NotNil(t, tlsConfig)
	keypair, err := tlsConfig.GetClientCertificate(nil)
	assert.Nil(t, err)
	assert.NotNil(t, keypair)
	assert.Equal(t, &expectedKeypair, keypair)
	assert.Equal(t, expectedCaCertPool, tlsConfig.RootCAs)
	// Check that our base option is honored.
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
}

func TestWatchedClientConfigRotation(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)
	logger, _ := test.NewNullLogger()

	expectedCaCertPool := x509.NewCertPool()
	if ok := expectedCaCertPool.AppendCertsFromPEM(rotatedHubbleServerCA); !ok {
		t.Fatal("AppendCertsFromPEM", rotatedHubbleServerCA)
	}
	expectedKeypair, err := tls.X509KeyPair(rotatedRelayClientCertificate, rotatedRelayClientPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	c, err := NewWatchedClientConfig(logger, hubble.caFiles, relay.certFile, relay.privkeyFile)
	assert.Nil(t, err)
	assert.NotNil(t, c)
	defer c.Stop()

	rotate(t, hubble, relay)
	<-time.After(testReloadDelay)

	tlsConfig := c.ClientConfig(&tls.Config{
		MinVersion: tls.VersionTLS13,
	})
	assert.NotNil(t, tlsConfig)
	keypair, err := tlsConfig.GetClientCertificate(nil)
	assert.Nil(t, err)
	assert.NotNil(t, keypair)
	assert.Equal(t, &expectedKeypair, keypair)
	assert.Equal(t, expectedCaCertPool, tlsConfig.RootCAs)
	// Check that our base option is honored.
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
}
