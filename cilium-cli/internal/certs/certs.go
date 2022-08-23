// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certs

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/cfssl/cli/genkey"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/k8s"
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

// GetOrCreateCASecret Returns a pointer to the secret data for the Cilium CA
// and true when it was created, false otherwise. If the Cilium CA does not
// already exist this function will generate a new one when createCA is true.
func (c *CertManager) GetOrCreateCASecret(ctx context.Context, caSecretName string, createCA bool) (*corev1.Secret, bool, error) {
	s, err := c.client.GetSecret(ctx, c.params.Namespace, caSecretName, metav1.GetOptions{})
	if !createCA || !errors.IsNotFound(err) {
		return s, false, err
	}
	// from here the CA Secret doesn't exists and we are requested to create
	// it.
	if err = c.GenerateCA(); err != nil {
		return nil, false, fmt.Errorf("unable to generate CA: %w", err)
	}

	if s, err = c.StoreCAInK8s(ctx); err != nil {
		return nil, false, fmt.Errorf("unable to store CA in secret: %w", err)
	}

	return s, true, nil
}

func (c *CertManager) LoadCAFromK8s(ctx context.Context, secret *corev1.Secret) error {
	if key, ok := secret.Data[defaults.CASecretKeyName]; ok {
		c.caKey = make([]byte, len(key))
		copy(c.caKey, key)
	} else {
		return fmt.Errorf("secret %q does not contain a key %q", defaults.CASecretName, defaults.CASecretKeyName)
	}

	if cert, ok := secret.Data[defaults.CASecretCertName]; ok {
		c.caCert = make([]byte, len(cert))
		copy(c.caCert, cert)
	} else {
		return fmt.Errorf("secret %q does not contain a key %q", defaults.CASecretName, defaults.CASecretCertName)
	}

	return nil
}

func (c *CertManager) StoreCAInK8s(ctx context.Context) (*corev1.Secret, error) {
	if len(c.caKey) == 0 || len(c.caCert) == 0 {
		return nil, fmt.Errorf("no CA available")
	}

	data := map[string][]byte{
		defaults.CASecretKeyName:  c.caKey,
		defaults.CASecretCertName: c.caCert,
	}

	secret, err := c.client.CreateSecret(ctx, c.params.Namespace, k8s.NewSecret(defaults.CASecretName, c.params.Namespace, data), metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to create secret %s/%s: %w", c.params.Namespace, defaults.CASecretName, err)
	}

	return secret, nil
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

// CACertBytes return the CA public certificate bytes, or nil when it is not
// set.
func (c *CertManager) CACertBytes() []byte {
	// NOTE: return a copy just to avoid the caller modifiying our CA
	// certificate.
	crt := make([]byte, len(c.caCert))
	copy(crt, c.caCert)
	return crt
}

// CAKeyBytes return the CA private certificate bytes, or nil when it is not
// set.
func (c *CertManager) CAKeyBytes() []byte {
	// NOTE: return a copy just to avoid the caller modifiying our CA
	// certificate.
	crt := make([]byte, len(c.caKey))
	copy(crt, c.caKey)
	return crt
}

// EncodeCertBytes returns an encoded format of the certificate bytes.
func EncodeCertBytes(cert []byte) string {
	return base64.StdEncoding.EncodeToString(cert)
}

// DecodeCertBytes returns a decoded format of the certificate bytes.
func DecodeCertBytes(cert string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(cert)
}
