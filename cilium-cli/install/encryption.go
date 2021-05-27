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

package install

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func generateRandomKey() (string, error) {
	random := make([]byte, 20)
	_, err := rand.Read(random)
	if err != nil {
		return "", fmt.Errorf("unable to generate random sequence for key: %w", err)
	}

	key := "3 rfc4106(gcm(aes)) "
	for _, c := range random {
		key += fmt.Sprintf("%02x", c)
	}
	key += " 128"

	return key, nil
}

func (k *K8sInstaller) createEncryptionSecret(ctx context.Context) error {
	// Check if secret already exists and reuse it
	_, err := k.client.GetSecret(ctx, k.params.Namespace, defaults.EncryptionSecretName, metav1.GetOptions{})
	if err == nil {
		k.Log("🔑 Found existing encryption secret %s", defaults.EncryptionSecretName)
		return nil
	}

	key, err := generateRandomKey()
	if err != nil {
		return err
	}

	data := map[string][]byte{"keys": []byte(key)}

	k.Log("🔑 Generated encryption secret %s", defaults.EncryptionSecretName)
	_, err = k.client.CreateSecret(ctx, k.params.Namespace, k8s.NewSecret(defaults.EncryptionSecretName, k.params.Namespace, data), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create encryption secret %s/%s: %w", k.params.Namespace, defaults.HubbleServerSecretName, err)
	}
	k.pushRollbackStep(func(ctx context.Context) {
		if err := k.client.DeleteSecret(ctx, k.params.Namespace, defaults.EncryptionSecretName, metav1.DeleteOptions{}); err != nil {
			k.Log("Cannot delete %s Secret: %s", defaults.EncryptionSecretName, err)
		}
	})

	return nil
}
