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

func TestNewWatchedServerConfigErrors(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)
	logger, _ := test.NewNullLogger()

	_, err := NewWatchedServerConfig(logger, relay.caFiles, "", hubble.privkeyFile)
	assert.Equal(t, ErrMissingCertFile, err)

	_, err = NewWatchedServerConfig(logger, relay.caFiles, hubble.certFile, "")
	assert.Equal(t, ErrMissingPrivkeyFile, err)
}

func TestWatchedServerConfigIsMutualTLS(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)
	logger, _ := test.NewNullLogger()

	tests := []struct {
		name        string
		constructor func() (*WatchedServerConfig, error)
		isMutualTLS bool
	}{
		{
			name: "keypair only",
			constructor: func() (*WatchedServerConfig, error) {
				return NewWatchedServerConfig(logger, nil, hubble.certFile, hubble.privkeyFile)
			},
			isMutualTLS: false,
		},
		{
			name: "CA and keypair",
			constructor: func() (*WatchedServerConfig, error) {
				return NewWatchedServerConfig(logger, relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			isMutualTLS: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			defer s.Stop()
			if tt.isMutualTLS {
				assert.True(t, s.IsMutualTLS())
			} else {
				assert.False(t, s.IsMutualTLS())
			}
		})
	}
}

func TestFutureWatchedServerConfig(t *testing.T) {
	dir, hubble, relay := directories(t)
	// don't call setup() yet, we only want the directories created without the
	// TLS files.
	defer cleanup(dir)
	logger, _ := test.NewNullLogger()

	ch, err := FutureWatchedServerConfig(logger, relay.caFiles, hubble.certFile, hubble.privkeyFile)
	assert.Nil(t, err)

	// the files don't exists, expect the config to not be ready yet.
	var s *WatchedServerConfig
	select {
	case <-ch:
		t.Fatal("FutureWatchedServerConfig should not be ready without the TLS files")
	case <-time.After(testReloadDelay):
	}

	setup(t, hubble, relay)

	// the files exists now, expect the watcher to become ready.
	select {
	case s = <-ch:
	case <-time.After(testReloadDelay):
		t.Fatal("FutureWatchedServerConfig should be ready one the TLS files exists")
	}
	s.Stop()
}

func TestNewWatchedServerConfig(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)
	logger, _ := test.NewNullLogger()

	expectedCaCertPool := x509.NewCertPool()
	if ok := expectedCaCertPool.AppendCertsFromPEM(initialRelayClientCA); !ok {
		t.Fatal("AppendCertsFromPEM", initialRelayClientCA)
	}
	expectedKeypair, err := tls.X509KeyPair(initialHubbleServerCertificate, initialHubbleServerPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	s, err := NewWatchedServerConfig(logger, relay.caFiles, hubble.certFile, hubble.privkeyFile)
	assert.Nil(t, err)
	assert.NotNil(t, s)
	defer s.Stop()

	generator := s.ServerConfig(&tls.Config{
		MinVersion: tls.VersionTLS13,
	})
	assert.NotNil(t, generator)
	tlsConfig, err := generator.GetConfigForClient(nil)
	assert.Nil(t, err)
	assert.NotNil(t, tlsConfig)
	assert.Equal(t, []tls.Certificate{expectedKeypair}, tlsConfig.Certificates)
	assert.Equal(t, expectedCaCertPool, tlsConfig.ClientCAs)
	assert.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
	// Check that our base option is honored.
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
}

func TestWatchedServerConfigRotation(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)
	logger, _ := test.NewNullLogger()

	expectedCaCertPool := x509.NewCertPool()
	if ok := expectedCaCertPool.AppendCertsFromPEM(rotatedRelayClientCA); !ok {
		t.Fatal("AppendCertsFromPEM", rotatedRelayClientCA)
	}
	expectedKeypair, err := tls.X509KeyPair(rotatedHubbleServerCertificate, rotatedHubbleServerPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	s, err := NewWatchedServerConfig(logger, relay.caFiles, hubble.certFile, hubble.privkeyFile)
	assert.Nil(t, err)
	assert.NotNil(t, s)
	defer s.Stop()

	rotate(t, hubble, relay)
	<-time.After(testReloadDelay)

	generator := s.ServerConfig(&tls.Config{
		MinVersion: tls.VersionTLS13,
	})
	assert.NotNil(t, generator)
	tlsConfig, err := generator.GetConfigForClient(nil)
	assert.Nil(t, err)
	assert.NotNil(t, tlsConfig)
	assert.Equal(t, []tls.Certificate{expectedKeypair}, tlsConfig.Certificates)
	assert.Equal(t, expectedCaCertPool, tlsConfig.ClientCAs)
	assert.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
	// Check that our base option is honored.
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
}
