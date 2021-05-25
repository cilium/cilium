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
	"fmt"
	"strings"
	"time"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (k *K8sInstaller) createHubbleServerCertificate(ctx context.Context) error {
	commonName := fmt.Sprintf("*.%s.hubble-grpc.cilium.io", strings.ReplaceAll(k.params.ClusterName, ".", "-"))
	certReq := &csr.CertificateRequest{
		Names:      []csr.Name{{C: "US", ST: "San Francisco", L: "CA"}},
		KeyRequest: csr.NewKeyRequest(),
		Hosts:      []string{commonName},
		CN:         commonName,
	}

	signConf := &config.Signing{
		Default: &config.SigningProfile{Expiry: 5 * 365 * 24 * time.Hour},
		Profiles: map[string]*config.SigningProfile{
			defaults.HubbleServerSecretName: {
				Expiry: 3 * 365 * 24 * time.Hour,
				Usage:  []string{"signing", "key encipherment", "server auth", "client auth"},
			},
		},
	}

	cert, key, err := k.certManager.GenerateCertificate(defaults.HubbleServerSecretName, certReq, signConf)
	if err != nil {
		return fmt.Errorf("unable to generate certificate %s: %w", defaults.HubbleServerSecretName, err)
	}

	data := map[string][]byte{
		corev1.TLSCertKey:         cert,
		corev1.TLSPrivateKeyKey:   key,
		defaults.CASecretCertName: k.certManager.CACertBytes(),
	}

	_, err = k.client.CreateSecret(ctx, k.params.Namespace, k8s.NewTLSSecret(defaults.HubbleServerSecretName, k.params.Namespace, data), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create secret %s/%s: %w", k.params.Namespace, defaults.HubbleServerSecretName, err)
	}

	return nil
}

func (k *K8sUninstaller) uninstallCerts(ctx context.Context) (err error) {
	if err = k.client.DeleteSecret(ctx, k.params.Namespace, defaults.HubbleServerSecretName, metav1.DeleteOptions{}); err != nil {
		err = fmt.Errorf("unable to delete secret %s/%s: %w", k.params.Namespace, defaults.HubbleServerSecretName, err)
	}
	if err2 := k.client.DeleteSecret(ctx, k.params.Namespace, defaults.CASecretName, metav1.DeleteOptions{}); err2 != nil {
		err2 = fmt.Errorf("unable to delete CA secret %s/%s: %w", k.params.Namespace, defaults.CASecretName, err2)
		if err == nil {
			err = err2
		}
	}

	return err
}

func (k *K8sInstaller) installCerts(ctx context.Context) error {
	if k.params.InheritCA != "" {
		caCluster, err := k8s.NewClient(k.params.InheritCA, "")
		if err != nil {
			return fmt.Errorf("unable to create Kubernetes client to derive CA from: %w", err)
		}

		s, err := caCluster.GetSecret(ctx, k.params.Namespace, defaults.CASecretName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("secret %s not found to derive CA from: %w", defaults.CASecretName, err)
		}

		newSecret := k8s.NewSecret(defaults.CASecretName, k.params.Namespace, s.Data)
		_, err = k.client.CreateSecret(ctx, k.params.Namespace, newSecret, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create secret to store CA: %w", err)
		}
		k.pushRollbackStep(func(ctx context.Context) {
			if err := k.client.DeleteSecret(ctx, k.params.Namespace, defaults.CASecretName, metav1.DeleteOptions{}); err != nil {
				k.Log("Cannot delete %s Secret: %w", defaults.CASecretName, err)
			}
		})
	}

	err := k.certManager.LoadCAFromK8s(ctx)
	if err != nil {
		k.Log("🔑 Generating CA...")
		if err := k.certManager.GenerateCA(); err != nil {
			return fmt.Errorf("unable to generate ca: %w", err)
		}

		if err := k.certManager.StoreCAInK8s(ctx); err != nil {
			return fmt.Errorf("unable to store CA in secret: %w", err)
		}
		k.pushRollbackStep(func(ctx context.Context) {
			if err := k.client.DeleteSecret(ctx, k.params.Namespace, defaults.CASecretName, metav1.DeleteOptions{}); err != nil {
				k.Log("Cannot delete %s Secret: %w", defaults.CASecretName, err)
			}
		})
	} else {
		k.Log("🔑 Found existing CA in secret %s", defaults.CASecretName)
	}

	k.Log("🔑 Generating certificates for Hubble...")
	if err := k.createHubbleServerCertificate(ctx); err != nil {
		return err
	}
	k.pushRollbackStep(func(ctx context.Context) {
		if err := k.client.DeleteSecret(ctx, k.params.Namespace, defaults.HubbleServerSecretName, metav1.DeleteOptions{}); err != nil {
			k.Log("Cannot delete %s Secret: %w", defaults.HubbleServerSecretName, err)
		}
	})

	return nil
}
