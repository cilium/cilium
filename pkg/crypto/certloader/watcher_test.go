// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certloader

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func TestNewWatcherError(t *testing.T) {
	dir, hubble, relay := directories(t)
	defer cleanup(dir)
	logger, _ := test.NewNullLogger()

	_, err := NewWatcher(logger, relay.caFiles, hubble.certFile, hubble.privkeyFile)
	assert.NotNil(t, err)
}

func TestNewWatcher(t *testing.T) {
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

	w, err := NewWatcher(logger, relay.caFiles, hubble.certFile, hubble.privkeyFile)
	assert.Nil(t, err)
	defer w.Stop()

	keypair, caCertPool := w.KeypairAndCACertPool()
	assert.Equal(t, &expectedKeypair, keypair)
	assert.Equal(t, expectedCaCertPool.Subjects(), caCertPool.Subjects())
}

func TestRotation(t *testing.T) {
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

	w, err := NewWatcher(logger, relay.caFiles, hubble.certFile, hubble.privkeyFile)
	assert.Nil(t, err)
	defer w.Stop()

	prevKeypairGeneration, prevCaCertPoolGeneration := w.generations()
	rotate(t, hubble, relay)

	// wait until both keypair and caCertPool have been reloaded
	ticker := time.NewTicker(testReloadDelay)
	defer ticker.Stop()
	for range ticker.C {
		keypairGeneration, caCertPoolGeneration := w.generations()
		keypairUpdated := keypairGeneration > prevKeypairGeneration
		caCertPoolUpdated := caCertPoolGeneration > prevCaCertPoolGeneration
		if keypairUpdated && caCertPoolUpdated {
			break
		}
	}

	keypair, caCertPool := w.KeypairAndCACertPool()
	assert.Equal(t, &expectedKeypair, keypair)
	assert.Equal(t, expectedCaCertPool.Subjects(), caCertPool.Subjects())
}

func TestFutureWatcherImmediately(t *testing.T) {
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

	ch, err := FutureWatcher(logger, relay.caFiles, hubble.certFile, hubble.privkeyFile)
	assert.Nil(t, err)

	// the files already exists, expect the watcher to be readily available.
	w := <-ch
	defer w.Stop()

	keypair, caCertPool := w.KeypairAndCACertPool()
	assert.Equal(t, &expectedKeypair, keypair)
	assert.Equal(t, expectedCaCertPool.Subjects(), caCertPool.Subjects())
}

func TestFutureWatcher(t *testing.T) {
	dir, hubble, relay := directories(t)
	// don't call setup() yet, we only want the directories created without the
	// TLS files.
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

	ch, err := FutureWatcher(logger, relay.caFiles, hubble.certFile, hubble.privkeyFile)
	assert.Nil(t, err)

	// the files don't exists, expect the watcher to not be ready yet.
	var w *Watcher
	select {
	case <-ch:
		t.Fatal("FutureWatcher should not be ready without the TLS files")
	case <-time.After(testReloadDelay):
	}

	setup(t, hubble, relay)

	// the files exists now, expect the watcher to become ready.
	w = <-ch
	defer w.Stop()

	keypair, caCertPool := w.KeypairAndCACertPool()
	assert.Equal(t, &expectedKeypair, keypair)
	assert.Equal(t, expectedCaCertPool.Subjects(), caCertPool.Subjects())
}

func TestKubernetesMount(t *testing.T) {
	dir, hubble := k8sDirectories(t)
	defer cleanup(dir)
	logger, _ := test.NewNullLogger()

	ch, err := FutureWatcher(logger, hubble.caFiles, hubble.certFile, hubble.privkeyFile)
	assert.Nil(t, err)

	// the files don't exists, expect the watcher to not be ready yet.
	select {
	case <-ch:
		t.Fatal("FutureWatcher should not be ready without the TLS files")
	case <-time.After(testReloadDelay):
	}

	// this will create the file
	k8Setup(t, dir)

	// the files exists now, expect the watcher to become ready.
	w := <-ch
	defer w.Stop()

	expectedInitialCaCertPool := x509.NewCertPool()
	if ok := expectedInitialCaCertPool.AppendCertsFromPEM(initialHubbleServerCA); !ok {
		t.Fatal("AppendCertsFromPEM", initialHubbleServerCA)
	}
	expectedInitialKeypair, err := tls.X509KeyPair(initialHubbleServerCertificate, initialHubbleServerPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	keypair, caCertPool := w.KeypairAndCACertPool()
	assert.Equal(t, &expectedInitialKeypair, keypair)
	assert.Equal(t, expectedInitialCaCertPool.Subjects(), caCertPool.Subjects())

	prevKeypairGeneration, prevCaCertPoolGeneration := w.generations()
	k8sRotate(t, dir)

	// wait until both keypair and caCertPool have been reloaded
	ticker := time.NewTicker(testReloadDelay)
	defer ticker.Stop()
	for range ticker.C {
		keypairGeneration, caCertPoolGeneration := w.generations()
		keypairUpdated := keypairGeneration > prevKeypairGeneration
		caCertPoolUpdated := caCertPoolGeneration > prevCaCertPoolGeneration
		if keypairUpdated && caCertPoolUpdated {
			break
		}
	}

	expectedRotatedCaCertPool := x509.NewCertPool()
	if ok := expectedRotatedCaCertPool.AppendCertsFromPEM(rotatedHubbleServerCA); !ok {
		t.Fatal("AppendCertsFromPEM", rotatedHubbleServerCA)
	}
	expectedRotatedKeypair, err := tls.X509KeyPair(rotatedHubbleServerCertificate, rotatedHubbleServerPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	keypair, caCertPool = w.KeypairAndCACertPool()
	assert.Equal(t, &expectedRotatedKeypair, keypair)
	assert.Equal(t, expectedRotatedCaCertPool.Subjects(), caCertPool.Subjects())
}
