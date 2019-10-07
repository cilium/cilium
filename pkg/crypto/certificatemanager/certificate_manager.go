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
	caName      = "ca.crt"
	publicName  = "public.crt"
	privateName = "private.crt"
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
func (m *Manager) GetTLSContext(ctx context.Context, tlsCtx *api.TLSContext) (ca, public, private string, err error) {
	// Give priority to local certificates
	if tlsCtx.CertificatesPath != nil {
		caBytes, _ := ioutil.ReadFile(filepath.Join(m.rootPath, caName))
		publicBytes, _ := ioutil.ReadFile(filepath.Join(m.rootPath, publicName))
		privateBytes, _ := ioutil.ReadFile(filepath.Join(m.rootPath, privateName))
		// We have found one of the files, that's all we need!
		if caBytes != nil || publicBytes != nil || privateBytes != nil {
			return string(caBytes), string(publicBytes), string(privateBytes), nil
		}
		err = fmt.Errorf("certificates not found in %s", m.rootPath)
	}
	if tlsCtx.K8sSecret != nil {
		ns := tlsCtx.K8sSecret.Namespace
		name := tlsCtx.K8sSecret.Name
		secrets, k8sErr := m.k8sClient.GetSecrets(ctx, ns, name)
		if k8sErr != nil {
			return "", "", "", k8sErr
		}
		caBytes, ok := secrets[caName]
		if ok {
			ca = string(caBytes)
		}
		publicBytes, ok := secrets[publicName]
		if ok {
			public = string(publicBytes)
		}
		privateBytes, ok := secrets[privateName]
		if ok {
			private = string(privateBytes)
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
