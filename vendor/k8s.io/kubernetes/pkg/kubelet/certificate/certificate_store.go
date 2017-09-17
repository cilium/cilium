/*
Copyright 2017 The Kubernetes Authors.

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

package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/glog"

	utilfile "k8s.io/kubernetes/pkg/util/file"
)

const (
	keyExtension  = ".key"
	certExtension = ".crt"
	pemExtension  = ".pem"
	currentPair   = "current"
	updatedPair   = "updated"
)

type fileStore struct {
	pairNamePrefix string
	certDirectory  string
	keyDirectory   string
	certFile       string
	keyFile        string
}

// NewFileStore returns a concrete implementation of a Store that is based on
// storing the cert/key pairs in a single file per pair on disk in the
// designated directory. When starting up it will look for the currently
// selected cert/key pair in:
//
// 1. ${certDirectory}/${pairNamePrefix}-current.pem - both cert and key are in the same file.
// 2. ${certFile}, ${keyFile}
// 3. ${certDirectory}/${pairNamePrefix}.crt, ${keyDirectory}/${pairNamePrefix}.key
//
// The first one found will be used. If rotation is enabled, future cert/key
// updates will be written to the ${certDirectory} directory and
// ${certDirectory}/${pairNamePrefix}-current.pem will be created as a soft
// link to the currently selected cert/key pair.
func NewFileStore(
	pairNamePrefix string,
	certDirectory string,
	keyDirectory string,
	certFile string,
	keyFile string) (Store, error) {

	s := fileStore{
		pairNamePrefix: pairNamePrefix,
		certDirectory:  certDirectory,
		keyDirectory:   keyDirectory,
		certFile:       certFile,
		keyFile:        keyFile,
	}
	if err := s.recover(); err != nil {
		return nil, err
	}
	return &s, nil
}

// recover checks if there is a certificate rotation that was interrupted while
// progress, and if so, attempts to recover to a good state.
func (s *fileStore) recover() error {
	// If the 'current' file doesn't exist, continue on with the recovery process.
	currentPath := filepath.Join(s.certDirectory, s.filename(currentPair))
	if exists, err := utilfile.FileExists(currentPath); err != nil {
		return err
	} else if exists {
		return nil
	}

	// If the 'updated' file exists, and it is a symbolic link, continue on
	// with the recovery process.
	updatedPath := filepath.Join(s.certDirectory, s.filename(updatedPair))
	if fi, err := os.Lstat(updatedPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	} else if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
		return fmt.Errorf("expected %q to be a symlink but it is a file", updatedPath)
	}

	// Move the 'updated' symlink to 'current'.
	if err := os.Rename(updatedPath, currentPath); err != nil {
		return fmt.Errorf("unable to rename %q to %q: %v", updatedPath, currentPath, err)
	}
	return nil
}

func (s *fileStore) Current() (*tls.Certificate, error) {
	pairFile := filepath.Join(s.certDirectory, s.filename(currentPair))
	if pairFileExists, err := utilfile.FileExists(pairFile); err != nil {
		return nil, err
	} else if pairFileExists {
		glog.Infof("Loading cert/key pair from %q.", pairFile)
		return loadFile(pairFile)
	}

	certFileExists, err := utilfile.FileExists(s.certFile)
	if err != nil {
		return nil, err
	}
	keyFileExists, err := utilfile.FileExists(s.keyFile)
	if err != nil {
		return nil, err
	}
	if certFileExists && keyFileExists {
		glog.Infof("Loading cert/key pair from (%q, %q).", s.certFile, s.keyFile)
		return loadX509KeyPair(s.certFile, s.keyFile)
	}

	c := filepath.Join(s.certDirectory, s.pairNamePrefix+certExtension)
	k := filepath.Join(s.keyDirectory, s.pairNamePrefix+keyExtension)
	certFileExists, err = utilfile.FileExists(c)
	if err != nil {
		return nil, err
	}
	keyFileExists, err = utilfile.FileExists(k)
	if err != nil {
		return nil, err
	}
	if certFileExists && keyFileExists {
		glog.Infof("Loading cert/key pair from (%q, %q).", c, k)
		return loadX509KeyPair(c, k)
	}

	noKeyErr := NoCertKeyError(
		fmt.Sprintf("no cert/key files read at %q, (%q, %q) or (%q, %q)",
			pairFile,
			s.certFile,
			s.keyFile,
			s.certDirectory,
			s.keyDirectory))
	return nil, &noKeyErr
}

func loadFile(pairFile string) (*tls.Certificate, error) {
	certBlock, keyBlock, err := loadCertKeyBlocks(pairFile)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(certBlock), pem.EncodeToMemory(keyBlock))
	if err != nil {
		return nil, fmt.Errorf("could not convert data from %q into cert/key pair: %v", pairFile, err)
	}
	certs, err := x509.ParseCertificates(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate data: %v", err)
	}
	cert.Leaf = certs[0]
	return &cert, nil
}

func loadCertKeyBlocks(pairFile string) (cert *pem.Block, key *pem.Block, err error) {
	data, err := ioutil.ReadFile(pairFile)
	if err != nil {
		return nil, nil, fmt.Errorf("could not load cert/key pair from %q: %v", pairFile, err)
	}
	certBlock, rest := pem.Decode(data)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("could not decode the first block from %q from expected PEM format", pairFile)
	}
	keyBlock, _ := pem.Decode(rest)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("could not decode the second block from %q from expected PEM format", pairFile)
	}
	return certBlock, keyBlock, nil
}

func (s *fileStore) Update(certData, keyData []byte) (*tls.Certificate, error) {
	ts := time.Now().Format("2006-01-02-15-04-05")
	pemFilename := s.filename(ts)

	if err := os.MkdirAll(s.certDirectory, 0755); err != nil {
		return nil, fmt.Errorf("could not create directory %q to store certificates: %v", s.certDirectory, err)
	}
	certPath := filepath.Join(s.certDirectory, pemFilename)

	f, err := os.OpenFile(certPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("could not open %q: %v", certPath, err)
	}
	defer f.Close()
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, fmt.Errorf("invalid certificate data")
	}
	pem.Encode(f, certBlock)
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, fmt.Errorf("invalid key data")
	}
	pem.Encode(f, keyBlock)

	cert, err := loadFile(certPath)
	if err != nil {
		return nil, err
	}

	if err := s.updateSymlink(certPath); err != nil {
		return nil, err
	}
	return cert, nil
}

// updateSymLink updates the current symlink to point to the file that is
// passed it. It will fail if there is a non-symlink file exists where the
// symlink is expected to be.
func (s *fileStore) updateSymlink(filename string) error {
	// If the 'current' file either doesn't exist, or is already a symlink,
	// proceed. Otherwise, this is an unrecoverable error.
	currentPath := filepath.Join(s.certDirectory, s.filename(currentPair))
	currentPathExists := false
	if fi, err := os.Lstat(currentPath); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
		return fmt.Errorf("expected %q to be a symlink but it is a file.", currentPath)
	} else {
		currentPathExists = true
	}

	// If the 'updated' file doesn't exist, proceed. If it exists but it is a
	// symlink, delete it.  Otherwise, this is an unrecoverable error.
	updatedPath := filepath.Join(s.certDirectory, s.filename(updatedPair))
	if fi, err := os.Lstat(updatedPath); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
		return fmt.Errorf("expected %q to be a symlink but it is a file.", updatedPath)
	} else {
		if err := os.Remove(updatedPath); err != nil {
			return fmt.Errorf("unable to remove %q: %v", updatedPath, err)
		}
	}

	// Check that the new cert/key pair file exists to avoid rotating to an
	// invalid cert/key.
	if filenameExists, err := utilfile.FileExists(filename); err != nil {
		return err
	} else if !filenameExists {
		return fmt.Errorf("file %q does not exist so it can not be used as the currently selected cert/key", filename)
	}

	// Create the 'updated' symlink pointing to the requested file name.
	if err := os.Symlink(filename, updatedPath); err != nil {
		return fmt.Errorf("unable to create a symlink from %q to %q: %v", updatedPath, filename, err)
	}

	// Replace the 'current' symlink.
	if currentPathExists {
		if err := os.Remove(currentPath); err != nil {
			return fmt.Errorf("unable to remove %q: %v", currentPath, err)
		}
	}
	if err := os.Rename(updatedPath, currentPath); err != nil {
		return fmt.Errorf("unable to rename %q to %q: %v", updatedPath, currentPath, err)
	}
	return nil
}

func (s *fileStore) filename(qualifier string) string {
	return s.pairNamePrefix + "-" + qualifier + pemExtension
}

// withoutExt returns the given filename after removing the extension. The
// extension to remove will be the result of filepath.Ext().
func withoutExt(filename string) string {
	return strings.TrimSuffix(filename, filepath.Ext(filename))
}

func loadX509KeyPair(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	certs, err := x509.ParseCertificates(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate data: %v", err)
	}
	cert.Leaf = certs[0]
	return &cert, nil
}
