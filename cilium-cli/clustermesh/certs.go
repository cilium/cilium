// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package clustermesh

import (
	"context"
	"fmt"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"
)

func (k *K8sClusterMesh) createClusterMeshServerCertificate(ctx context.Context) error {
	certReq := &csr.CertificateRequest{
		Names:      []csr.Name{{C: "US", ST: "San Francisco", L: "CA"}},
		KeyRequest: csr.NewKeyRequest(),
		Hosts: []string{
			"clustermesh-apiserver.cilium.io",
			"*.mesh.cilium.io",
			"localhost",
			"127.0.0.1",
		},
		CN: "ClusterMesh Server",
	}

	signConf := &config.Signing{
		Default: &config.SigningProfile{Expiry: 5 * 365 * 24 * time.Hour},
		Profiles: map[string]*config.SigningProfile{
			defaults.ClusterMeshServerSecretName: {
				Expiry: 5 * 365 * 24 * time.Hour,
				Usage:  []string{"signing", "key encipherment", "server auth", "client auth"},
			},
		},
	}

	cert, key, err := k.certManager.GenerateCertificate(defaults.ClusterMeshServerSecretName, certReq, signConf)
	if err != nil {
		return fmt.Errorf("unable to generate certificate %s: %w", defaults.ClusterMeshServerSecretName, err)
	}

	data := map[string][]byte{
		corev1.TLSCertKey:         cert,
		corev1.TLSPrivateKeyKey:   key,
		defaults.CASecretCertName: k.certManager.CACertBytes(),
	}

	_, err = k.client.CreateSecret(ctx, k.params.Namespace, k8s.NewTLSSecret(defaults.ClusterMeshServerSecretName, k.params.Namespace, data), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create secret %s/%s: %w", k.params.Namespace, defaults.ClusterMeshServerSecretName, err)
	}

	return nil
}

func (k *K8sClusterMesh) createClusterMeshAdminCertificate(ctx context.Context) error {
	certReq := &csr.CertificateRequest{
		Names:      []csr.Name{{C: "US", ST: "San Francisco", L: "CA"}},
		KeyRequest: csr.NewKeyRequest(),
		Hosts: []string{
			"localhost",
			"127.0.0.1",
		},
		CN: "root",
	}

	signConf := &config.Signing{
		Default: &config.SigningProfile{Expiry: 5 * 365 * 24 * time.Hour},
		Profiles: map[string]*config.SigningProfile{
			defaults.ClusterMeshAdminSecretName: {
				Expiry: 5 * 365 * 24 * time.Hour,
				Usage:  []string{"signing", "key encipherment", "server auth", "client auth"},
			},
		},
	}

	cert, key, err := k.certManager.GenerateCertificate(defaults.ClusterMeshAdminSecretName, certReq, signConf)
	if err != nil {
		return fmt.Errorf("unable to generate certificate %s: %w", defaults.ClusterMeshAdminSecretName, err)
	}

	data := map[string][]byte{
		corev1.TLSCertKey:         cert,
		corev1.TLSPrivateKeyKey:   key,
		defaults.CASecretCertName: k.certManager.CACertBytes(),
	}

	_, err = k.client.CreateSecret(ctx, k.params.Namespace, k8s.NewTLSSecret(defaults.ClusterMeshAdminSecretName, k.params.Namespace, data), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create secret %s/%s: %w", k.params.Namespace, defaults.ClusterMeshAdminSecretName, err)
	}

	return nil
}

func (k *K8sClusterMesh) createClusterMeshClientCertificate(ctx context.Context) error {
	certReq := &csr.CertificateRequest{
		Names:      []csr.Name{{C: "US", ST: "San Francisco", L: "CA"}},
		KeyRequest: csr.NewKeyRequest(),
		Hosts:      []string{""},
		CN:         "remote",
	}

	signConf := &config.Signing{
		Default: &config.SigningProfile{Expiry: 5 * 365 * 24 * time.Hour},
		Profiles: map[string]*config.SigningProfile{
			defaults.ClusterMeshClientSecretName: {
				Expiry: 5 * 365 * 24 * time.Hour,
				Usage:  []string{"signing", "key encipherment", "server auth", "client auth"},
			},
		},
	}

	cert, key, err := k.certManager.GenerateCertificate(defaults.ClusterMeshClientSecretName, certReq, signConf)
	if err != nil {
		return fmt.Errorf("unable to generate certificate %s: %w", defaults.ClusterMeshClientSecretName, err)
	}

	data := map[string][]byte{
		corev1.TLSCertKey:         cert,
		corev1.TLSPrivateKeyKey:   key,
		defaults.CASecretCertName: k.certManager.CACertBytes(),
	}

	_, err = k.client.CreateSecret(ctx, k.params.Namespace, k8s.NewTLSSecret(defaults.ClusterMeshClientSecretName, k.params.Namespace, data), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create secret %s/%s: %w", k.params.Namespace, defaults.ClusterMeshClientSecretName, err)
	}

	return nil
}

func (k *K8sClusterMesh) createClusterMeshExternalWorkloadCertificate(ctx context.Context) error {
	certReq := &csr.CertificateRequest{
		Names:      []csr.Name{{C: "US", ST: "San Francisco", L: "CA"}},
		KeyRequest: csr.NewKeyRequest(),
		Hosts:      []string{""},
		CN:         "externalworkload",
	}

	signConf := &config.Signing{
		Default: &config.SigningProfile{Expiry: 5 * 365 * 24 * time.Hour},
		Profiles: map[string]*config.SigningProfile{
			defaults.ClusterMeshExternalWorkloadSecretName: {
				Expiry: 5 * 365 * 24 * time.Hour,
				Usage:  []string{"signing", "key encipherment", "server auth", "client auth"},
			},
		},
	}

	cert, key, err := k.certManager.GenerateCertificate(defaults.ClusterMeshExternalWorkloadSecretName, certReq, signConf)
	if err != nil {
		return fmt.Errorf("unable to generate certificate %s: %w", defaults.ClusterMeshExternalWorkloadSecretName, err)
	}

	data := map[string][]byte{
		corev1.TLSCertKey:         cert,
		corev1.TLSPrivateKeyKey:   key,
		defaults.CASecretCertName: k.certManager.CACertBytes(),
	}

	_, err = k.client.CreateSecret(ctx, k.params.Namespace, k8s.NewTLSSecret(defaults.ClusterMeshExternalWorkloadSecretName, k.params.Namespace, data), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create secret %s/%s: %w", k.params.Namespace, defaults.ClusterMeshExternalWorkloadSecretName, err)
	}

	return nil
}

func (k *K8sClusterMesh) deleteCertificates(ctx context.Context) error {
	k.Log("🔥 Deleting ClusterMesh certificates...")
	k.client.DeleteSecret(ctx, k.params.Namespace, defaults.ClusterMeshServerSecretName, metav1.DeleteOptions{})
	k.client.DeleteSecret(ctx, k.params.Namespace, defaults.ClusterMeshAdminSecretName, metav1.DeleteOptions{})
	k.client.DeleteSecret(ctx, k.params.Namespace, defaults.ClusterMeshClientSecretName, metav1.DeleteOptions{})
	k.client.DeleteSecret(ctx, k.params.Namespace, defaults.ClusterMeshExternalWorkloadSecretName, metav1.DeleteOptions{})
	return nil
}

func (k *K8sClusterMesh) installCertificates(ctx context.Context) error {
	caSecret, created, err := k.certManager.GetOrCreateCASecret(ctx, defaults.CASecretName, k.params.CreateCA)
	if err != nil {
		k.Log("❌ Unable to get or create the Cilium CA Secret: %s", err)
		return err
	}

	if caSecret != nil {
		err = k.certManager.LoadCAFromK8s(ctx, caSecret)
		if err != nil {
			k.Log("❌ Unable to load Cilium CA: %s", err)
			return err
		}
		if created {
			k.Log("🔑 Created CA in secret %s", caSecret.Name)
		} else {
			k.Log("🔑 Found CA in secret %s", caSecret.Name)
		}
	}

	k.Log("🔑 Generating certificates for ClusterMesh...")

	if err := k.createClusterMeshServerCertificate(ctx); err != nil {
		return err
	}

	if err := k.createClusterMeshAdminCertificate(ctx); err != nil {
		return err
	}

	if err := k.createClusterMeshClientCertificate(ctx); err != nil {
		return err
	}

	return k.createClusterMeshExternalWorkloadCertificate(ctx)
}
