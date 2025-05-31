// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/defaults"
)

func (s *Encrypt) IPsecNewKey(ctx context.Context) error {
	ctx, cancelFn := context.WithTimeout(ctx, s.params.WaitDuration)
	defer cancelFn()

	if err := s.checkEncryptionSecretNotExists(ctx); err != nil {
		return err
	}

	newKey, err := createIPsecKey(s.params.IPsecKeyAuthAlgo)
	if err != nil {
		return fmt.Errorf("failed to create IPsec key: %w", err)
	}

	if err := s.createEncryptionSecret(ctx, newKey); err != nil {
		return err
	}

	_, err = fmt.Printf("IPsec key successfully created, new key SPI: %d\n", newKey.spi)
	return err
}

func (s *Encrypt) checkEncryptionSecretNotExists(ctx context.Context) error {
	_, err := s.client.GetSecret(ctx, s.params.CiliumNamespace, defaults.EncryptionSecretName, metav1.GetOptions{})
	if err == nil {
		return errors.New("IPsec secret already exists, rotate key if needed using `cilium encryption rotate-key` command")
	}
	if err.Error() != fmt.Sprintf(`secrets "%s" not found`, defaults.EncryptionSecretName) {
		return fmt.Errorf("failed to check if IPsec secret exists: %w", err)
	}
	return nil
}

func (s *Encrypt) createEncryptionSecret(ctx context.Context, key ipsecKey) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaults.EncryptionSecretName,
		},
		StringData: map[string]string{
			"keys": key.String(),
		},
	}
	_, err := s.client.CreateSecret(ctx, s.params.CiliumNamespace, secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create IPsec secret with new key: %w", err)
	}
	return nil
}

func createIPsecKey(algo string) (ipsecKey, error) {
	return rotators[algo](ipsecKey{algo: algo})
}
