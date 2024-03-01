// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium-cli/k8s"
)

// addSecrets adds one or more secret(s) resources to the test.
func (t *Test) addSecrets(secrets ...*corev1.Secret) error {
	if t.secrets == nil {
		t.secrets = make(map[string]*corev1.Secret)
	}

	for _, s := range secrets {
		if s == nil {
			return errors.New("cannot add nil Secret to test")
		}
		if s.Name == "" {
			return fmt.Errorf("cannot add Secret with empty name to test: %v", s)
		}
		if _, ok := t.secrets[s.Name]; ok {
			return fmt.Errorf("Secret with name %s already in test scope", s.Name)
		}

		t.secrets[s.Name] = s
	}

	return nil
}

// applySecrets applies all the test's registered secrets.
func (t *Test) applySecrets(ctx context.Context) error {
	if len(t.secrets) == 0 {
		return nil
	}

	for _, secret := range t.secrets {
		for _, client := range t.Context().clients.clients() {
			t.Infof("📜 Applying secret '%s' to namespace '%s'..", secret.Name, secret.Namespace)
			if _, err := updateOrCreateSecret(ctx, client, secret); err != nil {
				return fmt.Errorf("secret application failed: %w", err)
			}
		}
	}

	// Register a finalizer with the Test immediately to enable cleanup.
	t.finalizers = append(t.finalizers, func() error {
		// Use a detached context to make sure this call is not affected by
		// context cancellation. This deletion needs to happen event when the
		// user interrupted the program.
		if err := t.deleteSecrets(context.TODO()); err != nil {
			t.CiliumLogs(ctx)
			return err
		}

		return nil
	})

	t.Debugf("📜 Successfully applied %d secret(s)", len(t.secrets))

	return nil
}

// deleteSecrets deletes a given set of secrets from the cluster.
func (t *Test) deleteSecrets(ctx context.Context) error {
	if len(t.secrets) == 0 {
		return nil
	}

	// Delete all the Test's secrers from all clients.
	for _, secret := range t.secrets {
		t.Infof("📜 Deleting secret '%s' from namespace '%s'..", secret.Name, secret.Namespace)
		for _, client := range t.Context().clients.clients() {
			if err := deleteSecret(ctx, client, secret); err != nil {
				return fmt.Errorf("deleting secret: %w", err)
			}
		}
	}

	t.Debugf("📜 Successfully deleted %d secret(s)", len(t.secrets))

	return nil
}

func updateOrCreateSecret(ctx context.Context, client *k8s.Client, secret *corev1.Secret) (bool, error) {
	mod := false

	if existing, err := client.GetSecret(ctx, secret.Namespace, secret.Name, metav1.GetOptions{}); err == nil {
		// compare data map
		if len(existing.Data) != len(secret.Data) {
			mod = true
		} else {
			for k, v := range existing.Data {
				if v2, ok := secret.Data[k]; !ok || !bytes.Equal(v, v2) {
					mod = true
					break
				}
			}
		}

		_, err = client.UpdateSecret(ctx, secret.Namespace, secret, metav1.UpdateOptions{})
		return mod, err
	}

	// Creating, so a resource will definitely be modified.
	mod = true
	_, err := client.CreateSecret(ctx, secret.Namespace, secret, metav1.CreateOptions{})
	return mod, err
}

func deleteSecret(ctx context.Context, client *k8s.Client, secret *corev1.Secret) error {
	if err := client.DeleteSecret(ctx, secret.Namespace, secret.Name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("%s/%s/%s secret delete failed: %w", client.ClusterName(), secret.Namespace, secret.Name, err)
	}

	return nil
}
