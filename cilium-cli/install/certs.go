// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package install

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/k8s"
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
				k.Log("Cannot delete %s Secret: %s", defaults.CASecretName, err)
			}
		})
	}

	caSecret, created, err := k.certManager.GetOrCreateCASecret(ctx, defaults.CASecretName, true)
	if err != nil {
		k.Log("❌ Unable to get or create the Cilium CA Secret: %s", err)
		return err
	}

	if caSecret != nil {
		err = k.certManager.LoadCAFromK8s(ctx, caSecret)
		if err != nil {
			k.pushRollbackStep(func(ctx context.Context) {
				if err := k.client.DeleteSecret(ctx, k.params.Namespace, caSecret.Name, metav1.DeleteOptions{}); err != nil {
					k.Log("Cannot delete %s Secret: %s", caSecret.Name, err)
				}
			})
			return err
		}
		if created {
			k.Log("🔑 Created CA in secret %s", caSecret.Name)
		} else {
			k.Log("🔑 Found CA in secret %s", caSecret.Name)
		}
	}

	k.Log("🔑 Generating certificates for Hubble...")
	if err := k.createHubbleServerCertificate(ctx); err != nil {
		return err
	}
	k.pushRollbackStep(func(ctx context.Context) {
		if err := k.client.DeleteSecret(ctx, k.params.Namespace, defaults.HubbleServerSecretName, metav1.DeleteOptions{}); err != nil {
			k.Log("Cannot delete %s Secret: %s", defaults.HubbleServerSecretName, err)
		}
	})

	return nil
}
