// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certloader

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/lock"
)

// FileReloader is a set of TLS configuration files including custom CAs, and a
// certificate along with its private key (keypair) that can be reloaded
// dynamically via the Reload* functions.
type FileReloader struct {
	// caFiles, certFile, and privkeyFile are constants for the FileReloader's
	// lifetime, thus accessing them doesn't require acquiring the mutex.
	caFiles     []string
	certFile    string
	privkeyFile string
	mutex       lock.Mutex
	// fields below should only be accessed with mutex acquired as they may be
	// updated concurrently.
	caCertPool           *x509.CertPool
	caCertPoolGeneration uint // incremented when caCertPool is reloaded
	keypair              *tls.Certificate
	keypairGeneration    uint // incremented when keypair is reloaded
}

var (
	// ErrInvalidKeypair is returned when either the certificate or its
	// corresponding private key is missing.
	ErrInvalidKeypair = errors.New("certificate and private key are both required, but only one was provided")
)

// NewFileReloaderReady create and returns a FileReloader using the given file.
// The files are already loaded when this function returns, thus the returned
// FileReloader is readily usable.
func NewFileReloaderReady(caFiles []string, certFile, privkeyFile string) (*FileReloader, error) {
	r, err := NewFileReloader(caFiles, certFile, privkeyFile)
	if err != nil {
		return nil, err
	}

	// load the files for the first time.
	if _, _, err := r.Reload(); err != nil {
		return nil, err
	}

	return r, nil
}

// NewFileReloader create and returns a FileReloader using the given file. The
// files are not loaded when this function returns, and the caller is expected
// to call the Reload* functions until the returned FileReloader become ready.
func NewFileReloader(caFiles []string, certFile, privkeyFile string) (*FileReloader, error) {
	if certFile != "" && privkeyFile == "" {
		return nil, ErrInvalidKeypair
	}
	if certFile == "" && privkeyFile != "" {
		return nil, ErrInvalidKeypair
	}

	r := &FileReloader{
		caFiles:     caFiles,
		certFile:    certFile,
		privkeyFile: privkeyFile,
	}

	return r, nil
}

// HasKeypair returns true when the FileReloader contains both a certificate
// and its private key, false otherwise.
func (r *FileReloader) HasKeypair() bool {
	return r.certFile != "" && r.privkeyFile != ""
}

// HasCustomCA returns true when the FileReloader has custom CAs configured,
// false otherwise.
func (r *FileReloader) HasCustomCA() bool {
	return len(r.caFiles) > 0
}

// Ready returns true when the FileReloader is ready to be used, false
// otherwise.
func (r *FileReloader) Ready() bool {
	keypair, caCertPool := r.KeypairAndCACertPool()
	if r.HasKeypair() && keypair == nil {
		return false
	}
	if r.HasCustomCA() && caCertPool == nil {
		return false
	}
	return true
}

// KeypairAndCACertPool returns both the configured keypair and CAs. This
// function should only be called once the FileReloader is ready, see Ready().
func (r *FileReloader) KeypairAndCACertPool() (*tls.Certificate, *x509.CertPool) {
	r.mutex.Lock()
	keypair := r.keypair
	caCertPool := r.caCertPool
	r.mutex.Unlock()
	return keypair, caCertPool
}

// Reload update the caCertPool reading the caFiles, and the keypair reading
// certFile and privkeyFile.
func (r *FileReloader) Reload() (keypair *tls.Certificate, caCertPool *x509.CertPool, err error) {
	if r.HasKeypair() {
		keypair, err = r.readKeypair()
		if err != nil {
			return
		}
	}
	if r.HasCustomCA() {
		caCertPool, err = r.readCertificateAuthority()
		if err != nil {
			return
		}
	}

	r.mutex.Lock()
	if r.HasKeypair() {
		r.keypair = keypair
		r.keypairGeneration++
	}
	if r.HasCustomCA() {
		r.caCertPool = caCertPool
		r.caCertPoolGeneration++
	}
	r.mutex.Unlock()
	return
}

// ReloadKeypair update the keypair by reading certFile and privkeyFile.
func (r *FileReloader) ReloadKeypair() (*tls.Certificate, error) {
	if !r.HasKeypair() {
		return nil, nil
	}

	keypair, err := r.readKeypair()
	if err != nil {
		return nil, err
	}
	r.mutex.Lock()
	r.keypair = keypair
	r.keypairGeneration++
	r.mutex.Unlock()
	return keypair, nil
}

// ReloadCA update the caCertPool by reading the caFiles.
func (r *FileReloader) ReloadCA() (*x509.CertPool, error) {
	if !r.HasCustomCA() {
		return nil, nil
	}

	caCertPool, err := r.readCertificateAuthority()
	if err != nil {
		return nil, err
	}
	r.mutex.Lock()
	r.caCertPool = caCertPool
	r.caCertPoolGeneration++
	r.mutex.Unlock()
	return caCertPool, nil
}

// readKeypair read the certificate and private key.
func (r *FileReloader) readKeypair() (*tls.Certificate, error) {
	keypair, err := tls.LoadX509KeyPair(r.certFile, r.privkeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load keypair: %s", err)
	}
	return &keypair, nil
}

// readCertificateAuthority read the CA files.
func (r *FileReloader) readCertificateAuthority() (*x509.CertPool, error) {
	caCertPool := x509.NewCertPool()
	for _, path := range r.caFiles {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load cert %q: %s", path, err)
		}
		if ok := caCertPool.AppendCertsFromPEM(pem); !ok {
			return nil, fmt.Errorf("failed to load cert %q: must be PEM encoded", path)
		}
	}
	return caCertPool, nil
}

// generations returns the keypair and caCertPool generation counters.
func (r *FileReloader) generations() (uint, uint) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.keypairGeneration, r.caCertPoolGeneration
}
