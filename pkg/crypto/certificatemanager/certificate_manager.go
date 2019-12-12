// Copyright 2019 Authors of Cilium
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

package certificatemanager

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/cilium/cilium/pkg/policy/api"
)

const (
	caDefaultName      = "ca.crt"
	publicDefaultName  = "tls.crt"
	privateDefaultName = "tls.key"
)

type k8sClient interface {
	GetSecrets(ctx context.Context, ns, name string) (map[string][]byte, error)
}

// Manager will manage the way certificates are retrieved based in the given
// k8sClient and rootPath.
type Manager struct {
	rootPath  string
	k8sClient k8sClient
}

// NewManager returns a new manager.
func NewManager(certsRootPath string, k8sClient k8sClient) *Manager {
	return &Manager{
		rootPath:  certsRootPath,
		k8sClient: k8sClient,
	}
}

// GetTLSContext returns a new ca, public and private certificates found based
// in the given api.TLSContext.
func (m *Manager) GetTLSContext(ctx context.Context, tlsCtx *api.TLSContext, defaultNs string) (ca, public, private string, err error) {
	var caBytes, publicBytes, privateBytes []byte

	caMustExist := false
	caName := caDefaultName
	if tlsCtx.TrustedCA != "" {
		caName = tlsCtx.TrustedCA
		caMustExist = true
	}

	publicMustExist := false
	publicName := publicDefaultName
	if tlsCtx.Certificate != "" {
		publicName = tlsCtx.Certificate
		publicMustExist = true
	}

	privateMustExist := false
	privateName := privateDefaultName
	if tlsCtx.PrivateKey != "" {
		privateName = tlsCtx.PrivateKey
		privateMustExist = true
	}

	if tlsCtx.Secret != nil {
		ns := defaultNs
		if tlsCtx.Secret.Namespace != "" {
			ns = tlsCtx.Secret.Namespace
		}
		if tlsCtx.Secret.Name == "" {
			err = fmt.Errorf("Missing Secret name")
			return "", "", "", err
		}
		name := tlsCtx.Secret.Name

		// Give priority to local certificates
		certPath := filepath.Join(m.rootPath, ns, name)
		files, ioErr := ioutil.ReadDir(certPath)
		if ioErr != nil {
			err = fmt.Errorf("Certificates directory %s not found (%s)", certPath, ioErr)
		} else {
			for _, file := range files {
				var path string
				switch file.Name() {
				case caName:
					path = filepath.Join(certPath, caName)
					caBytes, ioErr = ioutil.ReadFile(path)
				case publicName:
					privateMustExist = true
					path = filepath.Join(certPath, publicName)
					publicBytes, ioErr = ioutil.ReadFile(path)
				case privateName:
					publicMustExist = true
					path = filepath.Join(certPath, privateName)
					privateBytes, ioErr = ioutil.ReadFile(path)
				}
				if ioErr != nil {
					err = fmt.Errorf("Error reading %s (%s)", path, ioErr)
				}
			}
			// Error out if required files are missing
			if caMustExist && (caBytes == nil || len(caBytes) == 0) {
				err = fmt.Errorf("Trusted CA %s cannot be read in %s: %s", caName, certPath, err)
				return "", "", "", err
			}
			if publicMustExist && (publicBytes == nil || len(publicBytes) == 0) {
				err = fmt.Errorf("Certificate %s cannot be read in %s: %s", publicName, certPath, err)
				return "", "", "", err
			}
			if privateMustExist && (privateBytes == nil || len(privateBytes) == 0) {
				err = fmt.Errorf("Private key %s cannot be read in %s: %s", privateName, certPath, err)
				return "", "", "", err
			}
			// We have found one of the files, that's all we need!
			if caBytes != nil || publicBytes != nil || privateBytes != nil {
				return string(caBytes), string(publicBytes), string(privateBytes), nil
			}
			err = fmt.Errorf("certificates not found in %s", certPath)
		}

		// Look for k8s secrets if not found locally
		secrets, k8sErr := m.k8sClient.GetSecrets(ctx, ns, name)
		if k8sErr != nil {
			return "", "", "", k8sErr
		}
		caBytes, ok := secrets[caName]
		if ok {
			ca = string(caBytes)
		} else if caMustExist {
			err = fmt.Errorf("Trusted CA %s cannot be found in k8s secret %s/%s", caName, ns, name)
			return "", "", "", err
		}
		publicBytes, ok := secrets[publicName]
		if ok {
			public = string(publicBytes)
		} else if publicMustExist {
			err = fmt.Errorf("Certificate %s cannot be found in k8s secret %s/%s", publicName, ns, name)
			return "", "", "", err
		}
		privateBytes, ok := secrets[privateName]
		if ok {
			private = string(privateBytes)
		} else if privateMustExist {
			err = fmt.Errorf("Private Key %s cannot be found in k8s secret %s/%s", privateName, ns, name)
			return "", "", "", err
		}
		if caBytes != nil || publicBytes != nil || privateBytes != nil {
			return ca, public, private, nil
		}
		if err != nil {
			err = fmt.Errorf("certificates not found locally in %s nor in k8s secret %s/%s ", m.rootPath, ns, name)
			return "", "", "", err
		}
		err = fmt.Errorf("certificates not found in k8s secret %s/%s", ns, name)
	}
	return "", "", "", err
}
