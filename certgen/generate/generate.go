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

package generate

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/cilium/cilium/certgen/option"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/cloudflare/cfssl/cli/genkey"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "generate")
)

// CA contains the data and metadata of the certificate and keyfile
type Cert struct {
	CommonName         string
	ValidityDuration   time.Duration
	Usage              []string
	K8sSecretName      string
	K8sSecretNamespace string

	CertBytes []byte
	KeyBytes  []byte
}

// NewCert creates a new certificate blueprint
func NewCert(
	commonName string,
	validityDuration time.Duration,
	usage []string,
	k8sSecretName string,
	k8sSecretNamespace string,
) *Cert {
	return &Cert{
		CommonName:         commonName,
		ValidityDuration:   validityDuration,
		Usage:              usage,
		K8sSecretName:      k8sSecretName,
		K8sSecretNamespace: k8sSecretNamespace,
	}
}

// Generate the certificate and keyfile and populate c.CertBytes and c.CertKey
func (c *Cert) Generate(ca *x509.Certificate, caSigner crypto.Signer) error {
	log.WithFields(logrus.Fields{
		"commonName":       c.CommonName,
		"validityDuration": c.ValidityDuration,
		"usage":            c.Usage,
	}).Info("Generating certificate")

	certRequest := &csr.CertificateRequest{
		CN:         c.CommonName,
		Hosts:      []string{c.CommonName},
		KeyRequest: csr.NewKeyRequest(),
	}

	g := &csr.Generator{Validator: genkey.Validator}
	csrBytes, keyBytes, err := g.ProcessRequest(certRequest)
	if err != nil {
		return err
	}

	policy := &config.Signing{
		Default: &config.SigningProfile{
			Usage:  c.Usage,
			Expiry: c.ValidityDuration,
		},
	}
	s, err := local.NewSigner(caSigner, ca, signer.DefaultSigAlgo(caSigner), policy)
	if err != nil {
		return err
	}

	signReq := signer.SignRequest{Request: string(csrBytes)}
	certBytes, err := s.Sign(signReq)
	if err != nil {
		return err
	}

	c.CertBytes = certBytes
	c.KeyBytes = keyBytes
	return nil
}

// StoreAsSecret creates or updates the certificate and keyfile in a K8s secret
func (c *Cert) StoreAsSecret(k8sClient *kubernetes.Clientset) error {
	if c.CertBytes == nil || c.KeyBytes == nil {
		return fmt.Errorf("cannot create secret %s/%s from empty certificate",
			c.K8sSecretNamespace, c.K8sSecretName)
	}

	log.WithFields(logrus.Fields{
		"namespace": c.K8sSecretNamespace,
		"name":      c.K8sSecretName,
	}).Info("Creating K8s Secret")

	secret := &v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      c.K8sSecretName,
			Namespace: c.K8sSecretNamespace,
		},
		Data: map[string][]byte{
			"tls.crt": c.CertBytes,
			"tls.key": c.KeyBytes,
		},
		Type: v1.SecretTypeTLS,
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
	defer cancel()

	k8sSecrets := k8sClient.CoreV1().Secrets(c.K8sSecretNamespace)
	_, err := k8sSecrets.Create(ctx, secret, meta_v1.CreateOptions{})
	if k8sErrors.IsAlreadyExists(err) {
		_, err = k8sSecrets.Update(ctx, secret, meta_v1.UpdateOptions{})
	}
	return err
}

// CA contains the data and metadata of the certificate authority
type CA struct {
	K8sConfigMapName      string
	K8sConfigMapNamespace string

	CACertBytes []byte
	CAKeyBytes  []byte

	CACert *x509.Certificate
	CAKey  crypto.Signer
}

// NewCA creates a new root CA blueprint
func NewCA(k8sConfigMapName, k8sConfigMapNamespace string) *CA {
	return &CA{
		K8sConfigMapName:      k8sConfigMapName,
		K8sConfigMapNamespace: k8sConfigMapNamespace,
	}
}

// loadKeyPair populates c.CACert/c.CAKey from c.CACertBytes/c.CAKeyBytes
func (c *CA) loadKeyPair() error {
	caCert, err := helpers.ParseCertificatePEM(c.CACertBytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA cert PEM: %w", err)
	}

	caKey, err := helpers.ParsePrivateKeyPEM(c.CAKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA key PEM: %w", err)
	}

	c.CACert = caCert
	c.CAKey = caKey
	return nil
}

// Generate the root certificate and keyfile. Populates c.CACertBytes and c.CAKeyBytes
func (c *CA) Generate(commonName string, validityDuration time.Duration) error {
	caCSR := &csr.CertificateRequest{
		CN: commonName,
		CA: &csr.CAConfig{
			Expiry: validityDuration.String(),
		},
		KeyRequest: csr.NewKeyRequest(),
	}
	caCertBytes, _, caKeyBytes, err := initca.New(caCSR)
	if err != nil {
		return err
	}

	c.CACertBytes = caCertBytes
	c.CAKeyBytes = caKeyBytes
	return c.loadKeyPair()
}

// LoadFromFile populates c.CACertBytes and c.CAKeyBytes by reading them from file.
func (c *CA) LoadFromFile(caCertFile, caKeyFile string) error {
	if caCertFile == "" || caKeyFile == "" {
		return errors.New("path for CA key and cert file must both be provided if CA is not generated")
	}

	caCertBytes, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return fmt.Errorf("failed to load CA cert file: %w", err)
	}

	caKeyBytes, err := ioutil.ReadFile(caKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load Hubble CA key file: %w", err)
	}

	c.CACertBytes = caCertBytes
	c.CAKeyBytes = caKeyBytes
	return c.loadKeyPair()
}

// StoreAsConfigMap creates or updates the CA certificate in a K8s configmap
func (c *CA) StoreAsConfigMap(k8sClient *kubernetes.Clientset) error {
	if c.CACertBytes == nil || c.CAKeyBytes == nil {
		return fmt.Errorf("cannot create configmap %s/%s from empty certificate",
			c.K8sConfigMapNamespace, c.K8sConfigMapName)
	}

	log.WithFields(logrus.Fields{
		"namespace": c.K8sConfigMapNamespace,
		"name":      c.K8sConfigMapName,
	}).Info("Creating K8s ConfigMap")

	configMap := &v1.ConfigMap{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      c.K8sConfigMapName,
			Namespace: c.K8sConfigMapNamespace,
		},
		BinaryData: map[string][]byte{
			"ca.crt": c.CACertBytes,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
	defer cancel()

	k8sConfigMaps := k8sClient.CoreV1().ConfigMaps(c.K8sConfigMapNamespace)
	_, err := k8sConfigMaps.Create(ctx, configMap, meta_v1.CreateOptions{})
	if k8sErrors.IsAlreadyExists(err) {
		_, err = k8sConfigMaps.Update(ctx, configMap, meta_v1.UpdateOptions{})
	}
	return err
}
