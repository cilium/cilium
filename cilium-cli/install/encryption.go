// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package install

import (
	"context"
	"crypto/rand"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/k8s"
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
