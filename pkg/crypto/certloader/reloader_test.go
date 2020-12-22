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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFileReloaderErrors(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	_, err := NewFileReloaderReady(relay.caFiles, hubble.certFile, "")
	assert.Equal(t, err, ErrInvalidKeypair)

	_, err = NewFileReloaderReady(relay.caFiles, "", hubble.privkeyFile)
	assert.Equal(t, err, ErrInvalidKeypair)

	_, err = NewFileReloader(relay.caFiles, hubble.certFile, "")
	assert.Equal(t, err, ErrInvalidKeypair)

	_, err = NewFileReloader(relay.caFiles, "", hubble.privkeyFile)
	assert.Equal(t, err, ErrInvalidKeypair)
}

func TestHasKeypair(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	tests := []struct {
		name        string
		constructor func() (*FileReloader, error)
		hasKeypair  bool
	}{
		{
			name: "empty (ready)",
			constructor: func() (*FileReloader, error) {
				return NewFileReloaderReady(nil, "", "")
			},
			hasKeypair: false,
		},
		{
			name: "empty",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(nil, "", "")
			},
			hasKeypair: false,
		},
		{
			name: "keypair only (ready)",
			constructor: func() (*FileReloader, error) {
				return NewFileReloaderReady(nil, hubble.certFile, hubble.privkeyFile)
			},
			hasKeypair: true,
		},
		{
			name: "keypair only",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(nil, hubble.certFile, hubble.privkeyFile)
			},
			hasKeypair: true,
		},
		{
			name: "CA only (ready)",
			constructor: func() (*FileReloader, error) {
				return NewFileReloaderReady(relay.caFiles, "", "")
			},
			hasKeypair: false,
		},
		{
			name: "CA only",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(relay.caFiles, "", "")
			},
			hasKeypair: false,
		},
		{
			name: "CA and keypair (ready)",
			constructor: func() (*FileReloader, error) {
				return NewFileReloaderReady(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			hasKeypair: true,
		},
		{
			name: "CA and keypair",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			hasKeypair: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			if tt.hasKeypair {
				assert.True(t, r.HasKeypair())
			} else {
				assert.False(t, r.HasKeypair())
			}
		})
	}
}

func TestHasCustomCA(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	tests := []struct {
		name        string
		constructor func() (*FileReloader, error)
		hasCustomCA bool
	}{
		{
			name: "empty (ready)",
			constructor: func() (*FileReloader, error) {
				return NewFileReloaderReady(nil, "", "")
			},
			hasCustomCA: false,
		},
		{
			name: "empty",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(nil, "", "")
			},
			hasCustomCA: false,
		},
		{
			name: "keypair only (ready)",
			constructor: func() (*FileReloader, error) {
				return NewFileReloaderReady(nil, hubble.certFile, hubble.privkeyFile)
			},
			hasCustomCA: false,
		},
		{
			name: "keypair only",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(nil, hubble.certFile, hubble.privkeyFile)
			},
			hasCustomCA: false,
		},
		{
			name: "CA only (ready)",
			constructor: func() (*FileReloader, error) {
				return NewFileReloaderReady(relay.caFiles, "", "")
			},
			hasCustomCA: true,
		},
		{
			name: "CA only",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(relay.caFiles, "", "")
			},
			hasCustomCA: true,
		},
		{
			name: "CA and keypair (ready)",
			constructor: func() (*FileReloader, error) {
				return NewFileReloaderReady(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			hasCustomCA: true,
		},
		{
			name: "CA and keypair",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			hasCustomCA: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			if tt.hasCustomCA {
				assert.True(t, r.HasCustomCA())
			} else {
				assert.False(t, r.HasCustomCA())
			}
		})
	}
}

func TestReady(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	tests := []struct {
		name        string
		constructor func() (*FileReloader, error)
		isReady     bool
	}{
		{
			name: "empty (ready)",
			constructor: func() (*FileReloader, error) {
				return NewFileReloaderReady(nil, "", "")
			},
			isReady: true,
		},
		{
			name: "empty",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(nil, "", "")
			},
			isReady: true,
		},
		{
			name: "keypair only (ready)",
			constructor: func() (*FileReloader, error) {
				return NewFileReloaderReady(nil, hubble.certFile, hubble.privkeyFile)
			},
			isReady: true,
		},
		{
			name: "keypair only",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(nil, hubble.certFile, hubble.privkeyFile)
			},
			isReady: false,
		},
		{
			name: "CA only (ready)",
			constructor: func() (*FileReloader, error) {
				return NewFileReloaderReady(relay.caFiles, "", "")
			},
			isReady: true,
		},
		{
			name: "CA only",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(relay.caFiles, "", "")
			},
			isReady: false,
		},
		{
			name: "CA and keypair (ready)",
			constructor: func() (*FileReloader, error) {
				return NewFileReloaderReady(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			isReady: true,
		},
		{
			name: "CA and keypair",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			isReady: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			if tt.isReady {
				assert.True(t, r.Ready())
			} else {
				assert.False(t, r.Ready())
			}
		})
	}
}

func TestKeypairAndCACertPool(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	hubbleCaCertPool := x509.NewCertPool()
	if ok := hubbleCaCertPool.AppendCertsFromPEM(initialRelayClientCA); !ok {
		t.Fatal("AppendCertsFromPEM", initialRelayClientCA)
	}

	hubbleKeypair, err := tls.X509KeyPair(initialHubbleServerCertificate, initialHubbleServerPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	tests := []struct {
		name               string
		constructor        func() (*FileReloader, error)
		expectedKeypair    *tls.Certificate
		expectedCaCertPool *x509.CertPool
	}{
		{
			name: "empty (ready)",
			constructor: func() (*FileReloader, error) {
				return NewFileReloaderReady(nil, "", "")
			},
			expectedKeypair:    nil,
			expectedCaCertPool: nil,
		},
		{
			name: "empty",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(nil, "", "")
			},
			expectedKeypair:    nil,
			expectedCaCertPool: nil,
		},
		{
			name: "keypair only (ready)",
			constructor: func() (*FileReloader, error) {
				return NewFileReloaderReady(nil, hubble.certFile, hubble.privkeyFile)
			},
			expectedKeypair:    &hubbleKeypair,
			expectedCaCertPool: nil,
		},
		{
			name: "keypair only",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(nil, hubble.certFile, hubble.privkeyFile)
			},
			expectedKeypair:    nil,
			expectedCaCertPool: nil,
		},
		{
			name: "CA only (ready)",
			constructor: func() (*FileReloader, error) {
				return NewFileReloaderReady(relay.caFiles, "", "")
			},
			expectedKeypair:    nil,
			expectedCaCertPool: hubbleCaCertPool,
		},
		{
			name: "CA only",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(relay.caFiles, "", "")
			},
			expectedKeypair:    nil,
			expectedCaCertPool: nil,
		},
		{
			name: "CA and keypair (ready)",
			constructor: func() (*FileReloader, error) {
				return NewFileReloaderReady(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			expectedKeypair:    &hubbleKeypair,
			expectedCaCertPool: hubbleCaCertPool,
		},
		{
			name: "CA and keypair",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			expectedKeypair:    nil,
			expectedCaCertPool: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			keypair, caCertPool := r.KeypairAndCACertPool()
			assert.Equal(t, tt.expectedKeypair, keypair)
			assert.Equal(t, tt.expectedCaCertPool, caCertPool)
		})
	}
}

func TestReload(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	hubbleCaCertPool := x509.NewCertPool()
	if ok := hubbleCaCertPool.AppendCertsFromPEM(initialRelayClientCA); !ok {
		t.Fatal("AppendCertsFromPEM", initialRelayClientCA)
	}

	hubbleKeypair, err := tls.X509KeyPair(initialHubbleServerCertificate, initialHubbleServerPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	tests := []struct {
		name               string
		constructor        func() (*FileReloader, error)
		expectedKeypair    *tls.Certificate
		expectedCaCertPool *x509.CertPool
	}{
		{
			name: "empty",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(nil, "", "")
			},
			expectedKeypair:    nil,
			expectedCaCertPool: nil,
		},
		{
			name: "keypair only",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(nil, hubble.certFile, hubble.privkeyFile)
			},
			expectedKeypair:    &hubbleKeypair,
			expectedCaCertPool: nil,
		},
		{
			name: "CA only",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(relay.caFiles, "", "")
			},
			expectedKeypair:    nil,
			expectedCaCertPool: hubbleCaCertPool,
		},
		{
			name: "CA and keypair",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			expectedKeypair:    &hubbleKeypair,
			expectedCaCertPool: hubbleCaCertPool,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			keypair, caCertPool, err := r.Reload()
			assert.Nil(t, err)
			assert.Equal(t, tt.expectedKeypair, keypair)
			assert.Equal(t, tt.expectedCaCertPool, caCertPool)

			keypair, caCertPool = r.KeypairAndCACertPool()
			assert.Equal(t, tt.expectedKeypair, keypair)
			assert.Equal(t, tt.expectedCaCertPool, caCertPool)
		})
	}
}

func TestReloadKeypair(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	hubbleKeypair, err := tls.X509KeyPair(initialHubbleServerCertificate, initialHubbleServerPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	tests := []struct {
		name               string
		constructor        func() (*FileReloader, error)
		expectedKeypair    *tls.Certificate
		expectedCaCertPool *x509.CertPool
	}{
		{
			name: "empty",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(nil, "", "")
			},
			expectedKeypair: nil,
		},
		{
			name: "keypair only",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(nil, hubble.certFile, hubble.privkeyFile)
			},
			expectedKeypair: &hubbleKeypair,
		},
		{
			name: "CA only",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(relay.caFiles, "", "")
			},
			expectedKeypair: nil,
		},
		{
			name: "CA and keypair",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			expectedKeypair: &hubbleKeypair,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			keypair, err := r.ReloadKeypair()
			assert.Nil(t, err)
			assert.Equal(t, tt.expectedKeypair, keypair)

			keypair, caCertPool := r.KeypairAndCACertPool()
			assert.Equal(t, tt.expectedKeypair, keypair)
			assert.Nil(t, caCertPool)
		})
	}
}

func TestReloadCA(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	hubbleCaCertPool := x509.NewCertPool()
	if ok := hubbleCaCertPool.AppendCertsFromPEM(initialRelayClientCA); !ok {
		t.Fatal("AppendCertsFromPEM", initialRelayClientCA)
	}

	tests := []struct {
		name               string
		constructor        func() (*FileReloader, error)
		expectedCaCertPool *x509.CertPool
	}{
		{
			name: "empty",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(nil, "", "")
			},
			expectedCaCertPool: nil,
		},
		{
			name: "keypair only",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(nil, hubble.certFile, hubble.privkeyFile)
			},
			expectedCaCertPool: nil,
		},
		{
			name: "CA only",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(relay.caFiles, "", "")
			},
			expectedCaCertPool: hubbleCaCertPool,
		},
		{
			name: "CA and keypair",
			constructor: func() (*FileReloader, error) {
				return NewFileReloader(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			expectedCaCertPool: hubbleCaCertPool,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			caCertPool, err := r.ReloadCA()
			assert.Nil(t, err)
			assert.Equal(t, tt.expectedCaCertPool, caCertPool)

			keypair, caCertPool := r.KeypairAndCACertPool()
			assert.Nil(t, keypair)
			assert.Equal(t, tt.expectedCaCertPool, caCertPool)
		})
	}
}

func TestReloadError(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	expectedCaCertPool := x509.NewCertPool()
	if ok := expectedCaCertPool.AppendCertsFromPEM(initialRelayClientCA); !ok {
		t.Fatal("AppendCertsFromPEM", initialRelayClientCA)
	}
	expectedKeypair, err := tls.X509KeyPair(initialHubbleServerCertificate, initialHubbleServerPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	r, err := NewFileReloaderReady(relay.caFiles, hubble.certFile, hubble.privkeyFile)
	assert.Nil(t, err)
	assert.NotNil(t, r)
	assert.True(t, r.Ready())

	keypair, caCertPool := r.KeypairAndCACertPool()
	assert.Equal(t, &expectedKeypair, keypair)
	assert.Equal(t, expectedCaCertPool, caCertPool)

	// delete one of the keypair file, so that reloading the keypair should
	// fail.
	if err = os.Remove(hubble.privkeyFile); err != nil {
		t.Fatal(err)
	}

	_, _, err = r.Reload()
	assert.NotNil(t, err)

	// we expect keypair and caCertPool to not have changed on failed reload.
	keypair, caCertPool = r.KeypairAndCACertPool()
	assert.Equal(t, &expectedKeypair, keypair)
	assert.Equal(t, expectedCaCertPool, caCertPool)
}
