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

package certs

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"

	"github.com/cloudflare/cfssl/cli/genkey"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CertManager struct {
	params Parameters

	caCert []byte
	caKey  []byte

	client k8sCertManagerImplementation
}

type k8sCertManagerImplementation interface {
	CreateSecret(ctx context.Context, namespace string, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error)
	DeleteSecret(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	GetSecret(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Secret, error)
}

type Parameters struct {
	Namespace string
}

func NewCertManager(client k8sCertManagerImplementation, p Parameters) *CertManager {
	return &CertManager{
		params: p,
		client: client,
	}
}

func (c *CertManager) LoadCAFromK8s(ctx context.Context) error {
	s, err := c.client.GetSecret(ctx, c.params.Namespace, defaults.CASecretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to get secret %s/%s: %w", c.params.Namespace, defaults.CASecretName, err)
	}

	if key, ok := s.Data[defaults.CASecretKeyName]; ok {
		c.caKey = make([]byte, len(key))
		copy(c.caKey, key)
	} else {
		return fmt.Errorf("secret %q does not contain a key %q", defaults.CASecretName, defaults.CASecretKeyName)
	}

	if cert, ok := s.Data[defaults.CASecretCertName]; ok {
		c.caCert = make([]byte, len(cert))
		copy(c.caCert, cert)
	} else {
		return fmt.Errorf("secret %q does not contain a key %q", defaults.CASecretName, defaults.CASecretCertName)
	}

	return nil
}

func (c *CertManager) StoreCAInK8s(ctx context.Context) error {
	if len(c.caKey) == 0 || len(c.caCert) == 0 {
		return fmt.Errorf("no CA available")
	}

	data := map[string][]byte{
		defaults.CASecretKeyName:  c.caKey,
		defaults.CASecretCertName: c.caCert,
	}

	_, err := c.client.CreateSecret(ctx, c.params.Namespace, k8s.NewSecret(defaults.CASecretName, c.params.Namespace, data), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create secret %s/%s: %w", c.params.Namespace, defaults.CASecretName, err)
	}

	return nil
}

func (c *CertManager) GenerateCA() error {
	cert, _, key, err := initca.New(&csr.CertificateRequest{
		Names:      []csr.Name{{C: "US", ST: "San Francisco", L: "CA", O: "Cilium", OU: "Cilium"}},
		KeyRequest: csr.NewKeyRequest(),
		CN:         "Cilium CA",
	})
	if err != nil {
		return err
	}

	c.caKey = key
	c.caCert = cert

	return nil
}

func (c *CertManager) GenerateCertificate(profile string, certReq *csr.CertificateRequest, signingConf *config.Signing) (certBytes []byte, keyBytes []byte, err error) {
	g := &csr.Generator{Validator: genkey.Validator}
	csrBytes, keyBytes, err := g.ProcessRequest(certReq)
	if err != nil {
		return nil, nil, err
	}
	parsedCa, err := helpers.ParseCertificatePEM(c.caCert)
	if err != nil {
		return nil, nil, err
	}
	priv, err := helpers.ParsePrivateKeyPEM(c.caKey)
	if err != nil {
		return nil, nil, err
	}
	s, err := local.NewSigner(priv, parsedCa, signer.DefaultSigAlgo(priv), signingConf)
	if err != nil {
		return nil, nil, err
	}
	signReq := signer.SignRequest{
		Request: string(csrBytes),
		Profile: profile,
	}
	certBytes, err = s.Sign(signReq)
	if err != nil {
		return nil, nil, err
	}
	return certBytes, keyBytes, nil
}
