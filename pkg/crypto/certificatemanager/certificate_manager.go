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
	"os"
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

// GetSecrets returns either local or k8s secrets, giving precedence for local secrets if configured.
// The 'ns' parameter is used as the secret namespace if 'secret.Namespace' is an empty string.
func (m *Manager) GetSecrets(ctx context.Context, secret *api.Secret, ns string) (string, map[string][]byte, error) {
	if secret == nil {
		return "", nil, fmt.Errorf("Secret must not be nil")
	}

	if secret.Namespace != "" {
		ns = secret.Namespace
	}

	if secret.Name == "" {
		return ns, nil, fmt.Errorf("Missing Secret name")
	}
	nsName := filepath.Join(ns, secret.Name)

	// Give priority to local secrets.
	// K8s API request is only done if the local secret directory can't be read!
	certPath := filepath.Join(m.rootPath, nsName)
	files, ioErr := os.ReadDir(certPath)
	if ioErr == nil {
		secrets := make(map[string][]byte, len(files))
		for _, file := range files {
			var bytes []byte

			path := filepath.Join(certPath, file.Name())
			bytes, ioErr = os.ReadFile(path)
			if ioErr == nil {
				secrets[file.Name()] = bytes
			}
		}
		// Return the (latest) error only if no secrets were found
		if len(secrets) == 0 && ioErr != nil {
			return nsName, nil, ioErr
		}
		return nsName, secrets, nil
	}
	secrets, err := m.k8sClient.GetSecrets(ctx, ns, secret.Name)
	return nsName, secrets, err
}

// GetTLSContext returns a new ca, public and private certificates found based
// in the given api.TLSContext.
func (m *Manager) GetTLSContext(ctx context.Context, tlsCtx *api.TLSContext, ns string) (ca, public, private string, err error) {
	name, secrets, err := m.GetSecrets(ctx, tlsCtx.Secret, ns)
	if err != nil {
		return "", "", "", err
	}

	caName := caDefaultName
	if tlsCtx.TrustedCA != "" {
		caName = tlsCtx.TrustedCA
	}
	caBytes, ok := secrets[caName]
	if ok {
		ca = string(caBytes)
	} else if tlsCtx.TrustedCA != "" {
		return "", "", "", fmt.Errorf("Trusted CA %s not found in secret %s", caName, name)
	}

	publicName := publicDefaultName
	if tlsCtx.Certificate != "" {
		publicName = tlsCtx.Certificate
	}
	publicBytes, ok := secrets[publicName]
	if ok {
		public = string(publicBytes)
	} else if tlsCtx.Certificate != "" {
		return "", "", "", fmt.Errorf("Certificate %s not found in secret %s", publicName, name)
	}

	privateName := privateDefaultName
	if tlsCtx.PrivateKey != "" {
		privateName = tlsCtx.PrivateKey
	}
	privateBytes, ok := secrets[privateName]
	if ok {
		private = string(privateBytes)
	} else if tlsCtx.PrivateKey != "" {
		return "", "", "", fmt.Errorf("Private Key %s not found in secret %s", privateName, name)
	}

	if caBytes == nil && publicBytes == nil && privateBytes == nil {
		return "", "", "", fmt.Errorf("TLS certificates not found in secret %s ", name)
	}

	return ca, public, private, nil
}

// GetSecretString returns a secret string stored in a k8s secret
func (m *Manager) GetSecretString(ctx context.Context, secret *api.Secret, ns string) (string, error) {
	name, secrets, err := m.GetSecrets(ctx, secret, ns)
	if err != nil {
		return "", err
	}

	if len(secrets) == 1 {
		// get the lone item by looping into the map
		for _, value := range secrets {
			return string(value), nil
		}
	}
	return "", fmt.Errorf("Secret %s must have exactly one item", name)
}
