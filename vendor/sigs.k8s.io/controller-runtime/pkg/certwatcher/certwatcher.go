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
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/go-logr/logr"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
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
	watcher     *fsnotify.Watcher
	interval    time.Duration
	log         logr.Logger

	certPath string
	keyPath  string

	cachedKeyPEMBlock []byte

	// callback is a function to be invoked when the certificate changes.
	callback func(tls.Certificate)
}

// New returns a new CertWatcher watching the given certificate and key.
func New(certPath, keyPath string) (*CertWatcher, error) {
	var err error

	cw := &CertWatcher{
		certPath: certPath,
		keyPath:  keyPath,
		interval: defaultWatchInterval,
		log:      log.WithValues("cert", certPath, "key", keyPath),
	}

	// Initial read of certificate and key.
	if err := cw.ReadCertificate(); err != nil {
		return nil, err
	}

	cw.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return cw, nil
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
	files := sets.New(cw.certPath, cw.keyPath)

	{
		var watchErr error
		if err := wait.PollUntilContextTimeout(ctx, 1*time.Second, 10*time.Second, true, func(ctx context.Context) (done bool, err error) {
			for _, f := range files.UnsortedList() {
				if err := cw.watcher.Add(f); err != nil {
					watchErr = err
					return false, nil //nolint:nilerr // We want to keep trying.
				}
				// We've added the watch, remove it from the set.
				files.Delete(f)
			}
			return true, nil
		}); err != nil {
			return fmt.Errorf("failed to add watches: %w", kerrors.NewAggregate([]error{err, watchErr}))
		}
	}

	go cw.Watch()

	ticker := time.NewTicker(cw.interval)
	defer ticker.Stop()

	cw.log.Info("Starting certificate poll+watcher", "interval", cw.interval)
	for {
		select {
		case <-ctx.Done():
			return cw.watcher.Close()
		case <-ticker.C:
			if err := cw.ReadCertificate(); err != nil {
				cw.log.Error(err, "failed read certificate")
			}
		}
	}
}

// Watch reads events from the watcher's channel and reacts to changes.
func (cw *CertWatcher) Watch() {
	for {
		select {
		case event, ok := <-cw.watcher.Events:
			// Channel is closed.
			if !ok {
				return
			}

			cw.handleEvent(event)
		case err, ok := <-cw.watcher.Errors:
			// Channel is closed.
			if !ok {
				return
			}

			cw.log.Error(err, "certificate watch error")
		}
	}
}

// updateCachedCertificate checks if the new certificate differs from the cache,
// updates it and returns the result if it was updated or not
func (cw *CertWatcher) updateCachedCertificate(cert *tls.Certificate, keyPEMBlock []byte) bool {
	cw.Lock()
	defer cw.Unlock()

	if cw.currentCert != nil &&
		bytes.Equal(cw.currentCert.Certificate[0], cert.Certificate[0]) &&
		bytes.Equal(cw.cachedKeyPEMBlock, keyPEMBlock) {
		cw.log.V(7).Info("certificate already cached")
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

	cw.log.Info("Updated current TLS certificate")

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

func (cw *CertWatcher) handleEvent(event fsnotify.Event) {
	// Only care about events which may modify the contents of the file.
	switch {
	case event.Op.Has(fsnotify.Write):
	case event.Op.Has(fsnotify.Create):
	case event.Op.Has(fsnotify.Chmod), event.Op.Has(fsnotify.Remove):
		// If the file was removed or renamed, re-add the watch to the previous name
		if err := cw.watcher.Add(event.Name); err != nil {
			cw.log.Error(err, "error re-watching file")
		}
	default:
		return
	}

	cw.log.V(1).Info("certificate event", "event", event)
	if err := cw.ReadCertificate(); err != nil {
		cw.log.Error(err, "error re-reading certificate")
	}
}

// NeedLeaderElection indicates that the cert-manager
// does not need leader election.
func (cw *CertWatcher) NeedLeaderElection() bool {
	return false
}
