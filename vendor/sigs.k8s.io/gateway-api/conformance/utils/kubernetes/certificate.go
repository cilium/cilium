/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kubernetes

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kvalidation "k8s.io/apimachinery/pkg/util/validation"
)

const (
	rsaBits  = 2048
	validFor = 365 * 24 * time.Hour
)

// MustCreateSelfSignedCertSecret creates a self-signed SSL certificate and stores it in a secret
func MustCreateSelfSignedCertSecret(t *testing.T, namespace, secretName string, hosts []string) *corev1.Secret {
	require.NotEmpty(t, hosts, "require a non-empty hosts for Subject Alternate Name values")

	var serverKey, serverCert bytes.Buffer

	require.NoError(t, generateRSACert(hosts, &serverKey, &serverCert, nil, nil), "failed to generate RSA certificate")

	return formatSecret(serverCert, serverKey, namespace, secretName)
}

// MustCreateCASignedCertSecret creates a CA-signed SSL certificate and stores it in a secret
func MustCreateCASignedCertSecret(t *testing.T, namespace, secretName string, hosts []string, ca *x509.Certificate, caPrivKey *rsa.PrivateKey) *corev1.Secret {
	require.NotEmpty(t, hosts, "require a non-empty hosts for Subject Alternate Name values")

	var serverCert, serverKey bytes.Buffer

	require.NoError(t, generateRSACert(hosts, &serverKey, &serverCert, ca, caPrivKey), "failed to generate CA signed RSA certificate")

	return formatSecret(serverCert, serverKey, namespace, secretName)
}

// formatSecret formats the server certificate, key, namespace, and secretName
// and converts it to a Kubernetes Secret object.
func formatSecret(serverCert bytes.Buffer, serverKey bytes.Buffer, namespace string, secretName string) *corev1.Secret {
	data := map[string][]byte{
		corev1.TLSCertKey:       serverCert.Bytes(),
		corev1.TLSPrivateKeyKey: serverKey.Bytes(),
	}

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      secretName,
		},
		Type: corev1.SecretTypeTLS,
		Data: data,
	}

	return newSecret
}

// generateRSACert generates a basic self-signed certificate if ca and caPrivKey are nil,
// otherwise it creates CA-signed cert with ca and caPrivkey input. Certs are valid for a year.
func generateRSACert(hosts []string, keyOut, certOut io.Writer, ca *x509.Certificate, caPrivKey *rsa.PrivateKey) error {
	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "default",
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if err = validateHost(h); err == nil {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if caPrivKey == nil {
		caPrivKey = priv
	}
	// If ca is nil, we create a self-signed certificate, e.g. template is the parent.
	if ca == nil {
		ca = &template
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, &priv.PublicKey, caPrivKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed creating cert: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return fmt.Errorf("failed creating key: %w", err)
	}

	return nil
}

// MustCreateCACertConfigMap will create a ConfigMap containing a CA Certificate, given a TLS Secret
// for that CA certificate.  Also returns the CA certificate.
func MustCreateCACertConfigMap(t *testing.T, namespace, configMapName string, hosts []string) (*corev1.ConfigMap, *x509.Certificate, *rsa.PrivateKey) {
	require.NotEmpty(t, hosts, "require a non-empty hosts for Subject Alternate Name values")

	var certData, keyData bytes.Buffer

	ca, caBytes, caPrivKey, err := generateCACert(hosts)
	if err != nil {
		t.Errorf("failed to generate CA certificate and key: %v", err)
		return nil, nil, nil
	}

	if err := pem.Encode(&certData, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes}); err != nil {
		t.Errorf("failed creating cert: %v", err)
		return nil, nil, nil
	}

	if err := pem.Encode(&keyData, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)}); err != nil {
		t.Errorf("failed creating key: %v", err)
		return nil, nil, nil
	}

	// Store the certificate in a ConfigMap.
	caConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      configMapName,
		},
		Data: map[string]string{
			"ca.crt": certData.String(),
			// Don't do this in production, this is just for conformance testing.
			"key.crt": keyData.String(),
		},
	}
	return caConfigMap, ca, caPrivKey
}

// generateCACert generates a CA and a CA-signed certificate valid for a year.
func generateCACert(hosts []string) (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	var caBytes []byte

	// Create the CA certificate template.
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2024),
		Subject: pkix.Name{
			Organization: []string{"Kubernetes Gateway API"},
			Country:      []string{"US"},
			CommonName:   "gatewayapi",
		},
		Issuer: pkix.Name{
			Organization: []string{"Kubernetes Gateway API"},
			Country:      []string{"US"},
			CommonName:   "kubernetes",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true, // Indicates this is a CA Certificate.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Ensure only valid hosts make it into the CA cert.
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			ca.IPAddresses = append(ca.IPAddresses, ip)
		} else if err := validateHost(h); err == nil {
			ca.DNSNames = append(ca.DNSNames, h)
		}
	}

	// Generate the private key to sign certificates.
	caPrivKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, caBytes, caPrivKey, fmt.Errorf("error generating key for CA: %v", err)
	}

	// Create the self-signed certificate using the CA certificate.
	caBytes, err = x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, caBytes, caPrivKey, fmt.Errorf("error creating CA: %v", err)
	}

	return ca, caBytes, caPrivKey, nil
}

// validateHost ensures that the host name length is no more than 253 characters.
// The only characters allowed in host name are alphanumeric characters, '-' or '.',
// and it must start and end with an alphanumeric character. A trailing dot is NOT allowed.
// The host name must in addition consist of one or more labels, with each label no more
// than 63 characters from the character set described above, and each label must start and
// end with an alphanumeric character.  Wildcards are handled specially.
// DO NOT USE for general validation purposes, this is just for the hostnames set up for
// conformance testing.
func validateHost(host string) error {
	// Remove wildcard if present.
	host, _ = strings.CutPrefix(host, "*.")

	errs := kvalidation.IsDNS1123Subdomain(host)
	if len(errs) != 0 {
		return fmt.Errorf("host %s must conform to DNS naming conventions: %v", host, errs)
	}

	labels := strings.Split(host, ".")
	for _, l := range labels {
		errs := kvalidation.IsDNS1123Label(l)
		if len(errs) != 0 {
			return fmt.Errorf("label %s in host %s must conform to DNS naming conventions: %v", l, host, errs)
		}
	}
	return nil
}
