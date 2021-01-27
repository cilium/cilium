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

package clustermesh

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		defaults.ClusterMeshServerSecretCertName: cert,
		defaults.ClusterMeshServerSecretKeyName:  key,
	}

	_, err = k.client.CreateSecret(ctx, k.params.Namespace, k8s.NewSecret(defaults.ClusterMeshServerSecretName, k.params.Namespace, data), metav1.CreateOptions{})
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
		CN: "ClusterMesh Admin",
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
		defaults.ClusterMeshAdminSecretCertName: cert,
		defaults.ClusterMeshAdminSecretKeyName:  key,
	}

	_, err = k.client.CreateSecret(ctx, k.params.Namespace, k8s.NewSecret(defaults.ClusterMeshAdminSecretName, k.params.Namespace, data), metav1.CreateOptions{})
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
		CN:         "ClusterMesh Client",
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
		defaults.ClusterMeshClientSecretCertName: cert,
		defaults.ClusterMeshClientSecretKeyName:  key,
	}

	_, err = k.client.CreateSecret(ctx, k.params.Namespace, k8s.NewSecret(defaults.ClusterMeshClientSecretName, k.params.Namespace, data), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create secret %s/%s: %w", k.params.Namespace, defaults.ClusterMeshClientSecretName, err)
	}

	return nil
}

func (k *K8sClusterMesh) deleteCertificates(ctx context.Context) error {
	k.Log("🔥 Deleting ClusterMesh certificates...")
	k.client.DeleteSecret(ctx, k.params.Namespace, defaults.ClusterMeshServerSecretName, metav1.DeleteOptions{})
	k.client.DeleteSecret(ctx, k.params.Namespace, defaults.ClusterMeshAdminSecretName, metav1.DeleteOptions{})
	k.client.DeleteSecret(ctx, k.params.Namespace, defaults.ClusterMeshClientSecretName, metav1.DeleteOptions{})
	return nil
}

func (k *K8sClusterMesh) installCertificates(ctx context.Context) error {
	err := k.certManager.LoadCAFromK8s(ctx)
	if err != nil {
		k.Log("❌ Cilium CA not found: %s", err)
		return err
	}
	k.Log("🔑 Found existing CA in secret %s", defaults.CASecretName)

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

	return nil
}
