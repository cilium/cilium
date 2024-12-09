/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certwatcher

import (
	"bytes"
	"context"
	"crypto/tls"
	"os"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/certwatcher/metrics"
	logf "sigs.k8s.io/controller-runtime/pkg/internal/log"
)

var log = logf.RuntimeLog.WithName("certwatcher")

const defaultWatchInterval = 10 * time.Second

// CertWatcher watches certificate and key files for changes.
// It always returns the cached version,
// but periodically reads and parses certificate and key for changes
// and calls an optional callback with the new certificate.
type CertWatcher struct {
	sync.RWMutex

	currentCert *tls.Certificate
	interval    time.Duration

	certPath string
	keyPath  string

	cachedKeyPEMBlock []byte

	// callback is a function to be invoked when the certificate changes.
	callback func(tls.Certificate)
}

// New returns a new CertWatcher watching the given certificate and key.
func New(certPath, keyPath string) (*CertWatcher, error) {
	cw := &CertWatcher{
		certPath: certPath,
		keyPath:  keyPath,
		interval: defaultWatchInterval,
	}

	return cw, cw.ReadCertificate()
}

// WithWatchInterval sets the watch interval and returns the CertWatcher pointer
func (cw *CertWatcher) WithWatchInterval(interval time.Duration) *CertWatcher {
	cw.interval = interval
	return cw
}

// RegisterCallback registers a callback to be invoked when the certificate changes.
func (cw *CertWatcher) RegisterCallback(callback func(tls.Certificate)) {
	cw.Lock()
	defer cw.Unlock()
	// If the current certificate is not nil, invoke the callback immediately.
	if cw.currentCert != nil {
		callback(*cw.currentCert)
	}
	cw.callback = callback
}

// GetCertificate fetches the currently loaded certificate, which may be nil.
func (cw *CertWatcher) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cw.RLock()
	defer cw.RUnlock()
	return cw.currentCert, nil
}

// Start starts the watch on the certificate and key files.
func (cw *CertWatcher) Start(ctx context.Context) error {
	ticker := time.NewTicker(cw.interval)
	defer ticker.Stop()

	log.Info("Starting certificate watcher")
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := cw.ReadCertificate(); err != nil {
				log.Error(err, "failed read certificate")
			}
		}
	}
}

// Watch used to read events from the watcher's channel and reacts to changes,
// it has currently no function and it's left here for backward compatibility until a future release.
//
// Deprecated: fsnotify has been removed and Start() is now polling instead.
func (cw *CertWatcher) Watch() {
}

// updateCachedCertificate checks if the new certificate differs from the cache,
// updates it and returns the result if it was updated or not
func (cw *CertWatcher) updateCachedCertificate(cert *tls.Certificate, keyPEMBlock []byte) bool {
	cw.Lock()
	defer cw.Unlock()

	if cw.currentCert != nil &&
		bytes.Equal(cw.currentCert.Certificate[0], cert.Certificate[0]) &&
		bytes.Equal(cw.cachedKeyPEMBlock, keyPEMBlock) {
		log.V(7).Info("certificate already cached")
		return false
	}
	cw.currentCert = cert
	cw.cachedKeyPEMBlock = keyPEMBlock
	return true
}

// ReadCertificate reads the certificate and key files from disk, parses them,
// and updates the current certificate on the watcher if updated. If a callback is set, it
// is invoked with the new certificate.
func (cw *CertWatcher) ReadCertificate() error {
	metrics.ReadCertificateTotal.Inc()
	certPEMBlock, err := os.ReadFile(cw.certPath)
	if err != nil {
		metrics.ReadCertificateErrors.Inc()
		return err
	}
	keyPEMBlock, err := os.ReadFile(cw.keyPath)
	if err != nil {
		metrics.ReadCertificateErrors.Inc()
		return err
	}

	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		metrics.ReadCertificateErrors.Inc()
		return err
	}

	if !cw.updateCachedCertificate(&cert, keyPEMBlock) {
		return nil
	}

	log.Info("Updated current TLS certificate")

	// If a callback is registered, invoke it with the new certificate.
	cw.RLock()
	defer cw.RUnlock()
	if cw.callback != nil {
		go func() {
			cw.callback(cert)
		}()
	}
	return nil
}
