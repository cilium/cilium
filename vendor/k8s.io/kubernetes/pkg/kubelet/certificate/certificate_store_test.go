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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/util/cert"
)

func TestUpdateSymlinkExistingFileError(t *testing.T) {
	dir, err := ioutil.TempDir("", "k8s-test-update-symlink")
	if err != nil {
		t.Fatalf("Unable to create the test directory %q: %v", dir, err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("Unable to clean up test directory %q: %v", dir, err)
		}
	}()
	pairFile := filepath.Join(dir, "kubelet-current.pem")
	if err := ioutil.WriteFile(pairFile, nil, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", pairFile, err)
	}

	s := fileStore{
		certDirectory:  dir,
		pairNamePrefix: "kubelet",
	}
	if err := s.updateSymlink(pairFile); err == nil {
		t.Errorf("Got no error, wanted to fail updating the symlink because there is a file there.")
	}
}

func TestUpdateSymlinkNewFileNotExist(t *testing.T) {
	dir, err := ioutil.TempDir("", "k8s-test-update-symlink")
	if err != nil {
		t.Fatalf("Unable to create the test directory %q: %v", dir, err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("Unable to clean up test directory %q: %v", dir, err)
		}
	}()
	oldPairFile := filepath.Join(dir, "kubelet-oldpair.pem")
	if err := ioutil.WriteFile(oldPairFile, nil, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", oldPairFile, err)
	}

	s := fileStore{
		certDirectory:  dir,
		pairNamePrefix: "kubelet",
	}
	if err := s.updateSymlink(oldPairFile); err != nil {
		t.Errorf("Got %v, wanted successful update of the symlink to point to %q", err, oldPairFile)
	}

	if _, err := os.Stat(oldPairFile); err != nil {
		t.Errorf("Got %v, wanted file %q to be there.", oldPairFile, err)
	}

	currentPairFile := filepath.Join(dir, "kubelet-current.pem")
	if fi, err := os.Lstat(currentPairFile); err != nil {
		t.Errorf("Got %v, wanted file %q to be there", currentPairFile, err)
	} else if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
		t.Errorf("Got %q not a symlink.", currentPairFile)
	}

	newPairFile := filepath.Join(dir, "kubelet-newpair.pem")
	if err := s.updateSymlink(newPairFile); err == nil {
		t.Errorf("Got no error, wanted to fail updating the symlink the file %q does not exist.", newPairFile)
	}
}

func TestUpdateSymlinkNoSymlink(t *testing.T) {
	dir, err := ioutil.TempDir("", "k8s-test-update-symlink")
	if err != nil {
		t.Fatalf("Unable to create the test directory %q: %v", dir, err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("Unable to clean up test directory %q: %v", dir, err)
		}
	}()
	pairFile := filepath.Join(dir, "kubelet-newfile.pem")
	if err := ioutil.WriteFile(pairFile, nil, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", pairFile, err)
	}

	s := fileStore{
		certDirectory:  dir,
		pairNamePrefix: "kubelet",
	}
	if err := s.updateSymlink(pairFile); err != nil {
		t.Errorf("Got error %v, wanted a new symlink to be created", err)
	}

	if _, err := os.Stat(pairFile); err != nil {
		t.Errorf("Got error %v, wanted file %q to be there", pairFile, err)
	}
	currentPairFile := filepath.Join(dir, "kubelet-current.pem")
	if fi, err := os.Lstat(currentPairFile); err != nil {
		t.Errorf("Got %v, wanted %q to be there", currentPairFile, err)
	} else if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
		t.Errorf("%q not a symlink, wanted a symlink.", currentPairFile)
	}
}

func TestUpdateSymlinkReplaceExistingSymlink(t *testing.T) {
	prefix := "kubelet"
	dir, err := ioutil.TempDir("", "k8s-test-update-symlink")
	if err != nil {
		t.Fatalf("Unable to create the test directory %q: %v", dir, err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("Unable to clean up test directory %q: %v", dir, err)
		}
	}()
	oldPairFile := filepath.Join(dir, prefix+"-oldfile.pem")
	if err := ioutil.WriteFile(oldPairFile, nil, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", oldPairFile, err)
	}
	newPairFile := filepath.Join(dir, prefix+"-newfile.pem")
	if err := ioutil.WriteFile(newPairFile, nil, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", newPairFile, err)
	}
	currentPairFile := filepath.Join(dir, prefix+"-current.pem")
	if err := os.Symlink(oldPairFile, currentPairFile); err != nil {
		t.Fatalf("unable to create a symlink from %q to %q: %v", currentPairFile, oldPairFile, err)
	}
	if resolved, err := os.Readlink(currentPairFile); err != nil {
		t.Fatalf("Got %v when attempting to resolve symlink %q", err, currentPairFile)
	} else if resolved != oldPairFile {
		t.Fatalf("Got %q as resolution of symlink %q, wanted %q", resolved, currentPairFile, oldPairFile)
	}

	s := fileStore{
		certDirectory:  dir,
		pairNamePrefix: prefix,
	}
	if err := s.updateSymlink(newPairFile); err != nil {
		t.Errorf("Got error %v, wanted a new symlink to be created", err)
	}

	if _, err := os.Stat(oldPairFile); err != nil {
		t.Errorf("Got error %v, wanted file %q to be there", oldPairFile, err)
	}
	if _, err := os.Stat(newPairFile); err != nil {
		t.Errorf("Got error %v, wanted file %q to be there", newPairFile, err)
	}
	if fi, err := os.Lstat(currentPairFile); err != nil {
		t.Errorf("Got %v, wanted %q to be there", currentPairFile, err)
	} else if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
		t.Errorf("%q not a symlink, wanted a symlink.", currentPairFile)
	}
	if resolved, err := os.Readlink(currentPairFile); err != nil {
		t.Fatalf("Got %v when attempting to resolve symlink %q", err, currentPairFile)
	} else if resolved != newPairFile {
		t.Fatalf("Got %q as resolution of symlink %q, wanted %q", resolved, currentPairFile, newPairFile)
	}
}

func TestLoadCertKeyBlocksNoFile(t *testing.T) {
	dir, err := ioutil.TempDir("", "k8s-test-load-cert-key-blocks")
	if err != nil {
		t.Fatalf("Unable to create the test directory %q: %v", dir, err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("Unable to clean up test directory %q: %v", dir, err)
		}
	}()

	pairFile := filepath.Join(dir, "kubelet-pair.pem")

	if _, _, err := loadCertKeyBlocks(pairFile); err == nil {
		t.Errorf("Got no error, but expected %q not found.", pairFile)
	}
}

func TestLoadCertKeyBlocksEmptyFile(t *testing.T) {
	dir, err := ioutil.TempDir("", "k8s-test-load-cert-key-blocks")
	if err != nil {
		t.Fatalf("Unable to create the test directory %q: %v", dir, err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("Unable to clean up test directory %q: %v", dir, err)
		}
	}()

	pairFile := filepath.Join(dir, "kubelet-pair.pem")
	if err := ioutil.WriteFile(pairFile, nil, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", pairFile, err)
	}

	if _, _, err := loadCertKeyBlocks(pairFile); err == nil {
		t.Errorf("Got no error, but expected %q not found.", pairFile)
	}
}

func TestLoadCertKeyBlocksPartialFile(t *testing.T) {
	dir, err := ioutil.TempDir("", "k8s-test-load-cert-key-blocks")
	if err != nil {
		t.Fatalf("Unable to create the test directory %q: %v", dir, err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("Unable to clean up test directory %q: %v", dir, err)
		}
	}()

	pairFile := filepath.Join(dir, "kubelet-pair.pem")
	if err := ioutil.WriteFile(pairFile, storeCertData.certificatePEM, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", pairFile, err)
	}

	if _, _, err := loadCertKeyBlocks(pairFile); err == nil {
		t.Errorf("Got no error, but expected %q invalid.", pairFile)
	}
}

func TestLoadCertKeyBlocks(t *testing.T) {
	dir, err := ioutil.TempDir("", "k8s-test-load-cert-key-blocks")
	if err != nil {
		t.Fatalf("Unable to create the test directory %q: %v", dir, err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("Unable to clean up test directory %q: %v", dir, err)
		}
	}()

	pairFile := filepath.Join(dir, "kubelet-pair.pem")
	data := append(storeCertData.certificatePEM, []byte("\n")...)
	data = append(data, storeCertData.keyPEM...)
	if err := ioutil.WriteFile(pairFile, data, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", pairFile, err)
	}

	certBlock, keyBlock, err := loadCertKeyBlocks(pairFile)
	if err != nil {
		t.Errorf("Got %v, but expected no error.", pairFile)
	}
	if certBlock.Type != cert.CertificateBlockType {
		t.Errorf("Got %q loaded from the pair file, expected a %q.", certBlock.Type, cert.CertificateBlockType)
	}
	if keyBlock.Type != cert.RSAPrivateKeyBlockType {
		t.Errorf("Got %q loaded from the pair file, expected a %q.", keyBlock.Type, cert.RSAPrivateKeyBlockType)
	}
}

func TestLoadFile(t *testing.T) {
	dir, err := ioutil.TempDir("", "k8s-test-load-cert-key-blocks")
	if err != nil {
		t.Fatalf("Unable to create the test directory %q: %v", dir, err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("Unable to clean up test directory %q: %v", dir, err)
		}
	}()

	pairFile := filepath.Join(dir, "kubelet-pair.pem")
	data := append(storeCertData.certificatePEM, []byte("\n")...)
	data = append(data, storeCertData.keyPEM...)
	if err := ioutil.WriteFile(pairFile, data, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", pairFile, err)
	}

	cert, err := loadFile(pairFile)
	if err != nil {
		t.Fatalf("Could not load certificate from disk: %v", err)
	}
	if cert == nil {
		t.Fatalf("There was no error, but no certificate data was returned.")
	}
	if cert.Leaf == nil {
		t.Fatalf("Got an empty leaf, expected private data.")
	}
}

func TestUpdateNoRotation(t *testing.T) {
	prefix := "kubelet-server"
	dir, err := ioutil.TempDir("", "k8s-test-certstore-current")
	if err != nil {
		t.Fatalf("Unable to create the test directory %q: %v", dir, err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("Unable to clean up test directory %q: %v", dir, err)
		}
	}()
	keyFile := filepath.Join(dir, "kubelet.key")
	if err := ioutil.WriteFile(keyFile, storeCertData.keyPEM, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", keyFile, err)
	}
	certFile := filepath.Join(dir, "kubelet.crt")
	if err := ioutil.WriteFile(certFile, storeCertData.certificatePEM, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", certFile, err)
	}

	s, err := NewFileStore(prefix, dir, dir, certFile, keyFile)
	if err != nil {
		t.Fatalf("Got %v while creating a new store.", err)
	}

	cert, err := s.Update(storeCertData.certificatePEM, storeCertData.keyPEM)
	if err != nil {
		t.Errorf("Got %v while updating certificate store.", err)
	}
	if cert == nil {
		t.Errorf("Got nil certificate, expected something real.")
	}
}

func TestUpdateRotation(t *testing.T) {
	prefix := "kubelet-server"
	dir, err := ioutil.TempDir("", "k8s-test-certstore-current")
	if err != nil {
		t.Fatalf("Unable to create the test directory %q: %v", dir, err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("Unable to clean up test directory %q: %v", dir, err)
		}
	}()
	keyFile := filepath.Join(dir, "kubelet.key")
	if err := ioutil.WriteFile(keyFile, storeCertData.keyPEM, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", keyFile, err)
	}
	certFile := filepath.Join(dir, "kubelet.crt")
	if err := ioutil.WriteFile(certFile, storeCertData.certificatePEM, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", certFile, err)
	}

	s, err := NewFileStore(prefix, dir, dir, certFile, keyFile)
	if err != nil {
		t.Fatalf("Got %v while creating a new store.", err)
	}

	cert, err := s.Update(storeCertData.certificatePEM, storeCertData.keyPEM)
	if err != nil {
		t.Fatalf("Got %v while updating certificate store.", err)
	}
	if cert == nil {
		t.Fatalf("Got nil certificate, expected something real.")
	}
}

func TestUpdateWithBadCertKeyData(t *testing.T) {
	prefix := "kubelet-server"
	dir, err := ioutil.TempDir("", "k8s-test-certstore-current")
	if err != nil {
		t.Fatalf("Unable to create the test directory %q: %v", dir, err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("Unable to clean up test directory %q: %v", dir, err)
		}
	}()
	keyFile := filepath.Join(dir, "kubelet.key")
	if err := ioutil.WriteFile(keyFile, storeCertData.keyPEM, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", keyFile, err)
	}
	certFile := filepath.Join(dir, "kubelet.crt")
	if err := ioutil.WriteFile(certFile, storeCertData.certificatePEM, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", certFile, err)
	}

	s, err := NewFileStore(prefix, dir, dir, certFile, keyFile)
	if err != nil {
		t.Fatalf("Got %v while creating a new store.", err)
	}

	cert, err := s.Update([]byte{0, 0}, storeCertData.keyPEM)
	if err == nil {
		t.Fatalf("Got no error while updating certificate store with invalid data.")
	}
	if cert != nil {
		t.Fatalf("Got %v certificate returned from the update, expected nil.", cert)
	}
}

func TestCurrentPairFile(t *testing.T) {
	prefix := "kubelet-server"
	dir, err := ioutil.TempDir("", "k8s-test-certstore-current")
	if err != nil {
		t.Fatalf("Unable to create the test directory %q: %v", dir, err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("Unable to clean up test directory %q: %v", dir, err)
		}
	}()
	pairFile := filepath.Join(dir, prefix+"-pair.pem")
	data := append(storeCertData.certificatePEM, []byte("\n")...)
	data = append(data, storeCertData.keyPEM...)
	if err := ioutil.WriteFile(pairFile, data, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", pairFile, err)
	}
	currentFile := filepath.Join(dir, prefix+"-current.pem")
	if err := os.Symlink(pairFile, currentFile); err != nil {
		t.Fatalf("unable to create a symlink from %q to %q: %v", currentFile, pairFile, err)
	}

	store, err := NewFileStore("kubelet-server", dir, dir, "", "")
	if err != nil {
		t.Fatalf("Failed to initialize certificate store: %v", err)
	}

	cert, err := store.Current()
	if err != nil {
		t.Fatalf("Could not load certificate from disk: %v", err)
	}
	if cert == nil {
		t.Fatalf("There was no error, but no certificate data was returned.")
	}
	if cert.Leaf == nil {
		t.Fatalf("Got an empty leaf, expected private data.")
	}
}

func TestCurrentCertKeyFiles(t *testing.T) {
	prefix := "kubelet-server"
	dir, err := ioutil.TempDir("", "k8s-test-certstore-current")
	if err != nil {
		t.Fatalf("Unable to create the test directory %q: %v", dir, err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("Unable to clean up test directory %q: %v", dir, err)
		}
	}()
	certFile := filepath.Join(dir, "kubelet.crt")
	if err := ioutil.WriteFile(certFile, storeCertData.certificatePEM, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", certFile, err)
	}
	keyFile := filepath.Join(dir, "kubelet.key")
	if err := ioutil.WriteFile(keyFile, storeCertData.keyPEM, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", keyFile, err)
	}

	store, err := NewFileStore(prefix, dir, dir, certFile, keyFile)
	if err != nil {
		t.Fatalf("Failed to initialize certificate store: %v", err)
	}

	cert, err := store.Current()
	if err != nil {
		t.Fatalf("Could not load certificate from disk: %v", err)
	}
	if cert == nil {
		t.Fatalf("There was no error, but no certificate data was returned.")
	}
	if cert.Leaf == nil {
		t.Fatalf("Got an empty leaf, expected private data.")
	}
}

func TestCurrentNoFiles(t *testing.T) {
	dir, err := ioutil.TempDir("", "k8s-test-certstore-current")
	if err != nil {
		t.Fatalf("Unable to create the test directory %q: %v", dir, err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("Unable to clean up test directory %q: %v", dir, err)
		}
	}()

	store, err := NewFileStore("kubelet-server", dir, dir, "", "")
	if err != nil {
		t.Fatalf("Failed to initialize certificate store: %v", err)
	}

	cert, err := store.Current()
	if err == nil {
		t.Fatalf("Got no error, expected an error because the cert/key files don't exist.")
	}
	if _, ok := err.(*NoCertKeyError); !ok {
		t.Fatalf("Got error %v, expected NoCertKeyError.", err)
	}
	if cert != nil {
		t.Fatalf("Got certificate, expected no certificate because the cert/key files don't exist.")
	}
}
