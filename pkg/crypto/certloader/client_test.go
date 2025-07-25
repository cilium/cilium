// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certloader

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

func TestWatchedClientConfigIsMutualTLS(t *testing.T) {
	t.Cleanup(func() {
		goleak.VerifyNone(t)
	})

	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)
	logger := hivetest.Logger(t)

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

func TestFutureWatchedClientConfig(t *testing.T) {
	t.Cleanup(func() {
		goleak.VerifyNone(t)
	})

	dir, hubble, relay := directories(t)
	// don't call setup() yet, we only want the directories created without the
	// TLS files.
	defer cleanup(dir)
	logger := hivetest.Logger(t)

	ch, err := FutureWatchedClientConfig(t.Context(), logger, relay.caFiles, hubble.certFile, hubble.privkeyFile)
	assert.NoError(t, err)

	// the files don't exists, expect the config to not be ready yet.
	select {
	case <-ch:
		t.Fatal("FutureWatchedClientConfig should not be ready without the TLS files")
	case <-time.After(testReloadDelay):
	}

	setup(t, hubble, relay)

	// the files exists now, expect the watcher to become ready.
	s := <-ch
	if assert.NotNil(t, s) {
		s.Stop()
	}
}

func TestNewWatchedClientConfig(t *testing.T) {
	t.Cleanup(func() {
		goleak.VerifyNone(t)
	})

	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)
	logger := hivetest.Logger(t)

	expectedCaCertPool := x509.NewCertPool()
	if ok := expectedCaCertPool.AppendCertsFromPEM(initialHubbleServerCA); !ok {
		t.Fatal("AppendCertsFromPEM", initialHubbleServerCA)
	}
	expectedKeypair, err := tls.X509KeyPair(initialRelayClientCertificate, initialRelayClientPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	c, err := NewWatchedClientConfig(logger, hubble.caFiles, relay.certFile, relay.privkeyFile)
	assert.NoError(t, err)
	assert.NotNil(t, c)
	defer c.Stop()

	tlsConfig := c.ClientConfig(&tls.Config{
		MinVersion: tls.VersionTLS13,
	})
	assert.NotNil(t, tlsConfig)
	keypair, err := tlsConfig.GetClientCertificate(nil)
	assert.NoError(t, err)
	assert.NotNil(t, keypair)
	assert.Equal(t, &expectedKeypair, keypair)
	assert.Equal(t, expectedCaCertPool.Subjects(), tlsConfig.RootCAs.Subjects())
	// Check that our base option is honored.
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
}

func TestNewWatchedClientConfigWithoutClientCert(t *testing.T) {
	t.Cleanup(func() {
		goleak.VerifyNone(t)
	})

	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)
	logger := hivetest.Logger(t)

	expectedCaCertPool := x509.NewCertPool()
	if ok := expectedCaCertPool.AppendCertsFromPEM(initialHubbleServerCA); !ok {
		t.Fatal("AppendCertsFromPEM", initialHubbleServerCA)
	}

	c, err := NewWatchedClientConfig(logger, hubble.caFiles, "", "")
	assert.NoError(t, err)
	assert.NotNil(t, c)
	defer c.Stop()

	tlsConfig := c.ClientConfig(&tls.Config{
		MinVersion: tls.VersionTLS13,
	})
	assert.NotNil(t, tlsConfig)
	// GetClientCertificate should be nil when a client keypair isn't configured
	assert.Nil(t, tlsConfig.GetClientCertificate)
}

func TestWatchedClientConfigRotation(t *testing.T) {
	t.Cleanup(func() {
		goleak.VerifyNone(t)
	})

	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)
	logger := hivetest.Logger(t)

	expectedCaCertPool := x509.NewCertPool()
	if ok := expectedCaCertPool.AppendCertsFromPEM(rotatedHubbleServerCA); !ok {
		t.Fatal("AppendCertsFromPEM", rotatedHubbleServerCA)
	}
	expectedKeypair, err := tls.X509KeyPair(rotatedRelayClientCertificate, rotatedRelayClientPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	c, err := NewWatchedClientConfig(logger, hubble.caFiles, relay.certFile, relay.privkeyFile)
	assert.NoError(t, err)
	assert.NotNil(t, c)
	defer c.Stop()

	prevKeypairGeneration, prevCaCertPoolGeneration := c.generations()
	rotate(t, hubble, relay)

	// wait until both keypair and caCertPool have been reloaded
	ticker := time.NewTicker(testReloadDelay)
	defer ticker.Stop()
	for range ticker.C {
		keypairGeneration, caCertPoolGeneration := c.generations()
		keypairUpdated := keypairGeneration > prevKeypairGeneration
		caCertPoolUpdated := caCertPoolGeneration > prevCaCertPoolGeneration
		if keypairUpdated && caCertPoolUpdated {
			break
		}
	}

	tlsConfig := c.ClientConfig(&tls.Config{
		MinVersion: tls.VersionTLS13,
	})
	assert.NotNil(t, tlsConfig)
	keypair, err := tlsConfig.GetClientCertificate(nil)
	assert.NoError(t, err)
	assert.NotNil(t, keypair)
	assert.Equal(t, &expectedKeypair, keypair)
	assert.Equal(t, expectedCaCertPool.Subjects(), tlsConfig.RootCAs.Subjects())
	// Check that our base option is honored.
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
}
