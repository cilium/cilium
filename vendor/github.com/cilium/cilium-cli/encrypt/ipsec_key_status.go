// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import (
	"context"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/status"
)

// IPsecKeyStatus displays IPsec key.
func (s *Encrypt) IPsecKeyStatus(ctx context.Context) error {
	ctx, cancelFn := context.WithTimeout(ctx, s.params.WaitDuration)
	defer cancelFn()

	secret, err := s.client.GetSecret(ctx, s.params.CiliumNamespace, defaults.EncryptionSecretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to fetch IPsec secret: %s", err)
	}

	if key, ok := secret.Data["keys"]; ok {
		return printIPsecKey(string(key), s.params.Output)
	}
	return fmt.Errorf("IPsec keys not found in the secret: %s", defaults.EncryptionSecretName)
}

type ipsecKeyStatus struct {
	Key string `json:"ipsec-key"`
}

func printIPsecKey(key string, format string) error {
	if format == status.OutputJSON {
		js, err := json.MarshalIndent(ipsecKeyStatus{Key: key}, "", " ")
		if err != nil {
			return err
		}
		_, err = fmt.Println(string(js))
		return err
	}
	_, err := fmt.Printf("IPsec key: %s\n", key)
	return err
}
