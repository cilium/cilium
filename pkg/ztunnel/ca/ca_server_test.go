// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/endpoint"
	testendpointmanager "github.com/cilium/cilium/pkg/testutils/endpointmanager"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

// fakeEndpointManager wraps the shared panic-by-default mock and supplies the
// single method exercised by the CA server test.
type fakeEndpointManager struct {
	*testendpointmanager.MockEndpointManager
	getEndpointsByServiceAccount func(namespace, serviceAccount string) []*endpoint.Endpoint
}

func (f *fakeEndpointManager) GetEndpointsByServiceAccount(namespace, serviceAccount string) []*endpoint.Endpoint {
	return f.getEndpointsByServiceAccount(namespace, serviceAccount)
}

//	Serial Number:
//	    65:09:76:9c:41:d2:d8:ba:5c:f4:2f:df:98:e5:d5:b8
//	Signature Algorithm: sha256WithRSAEncryption
//	Issuer: O=cluster.local
//	Validity
//	    Not Before: Jun 25 13:49:10 2025 GMT
//	    Not After : Jun 23 13:49:10 2035 GMT
//	Subject: O=cluster.local
//	Subject Public Key Info:
//	    Public Key Algorithm: rsaEncryption
//	        Public-Key: (2048 bit)
//	        Modulus:
//	        Exponent: 65537 (0x10001)
//	X509v3 extensions:
//	    X509v3 Key Usage: critical
//	        Certificate Sign
//	    X509v3 Basic Constraints: critical
//	        CA:TRUE
//	    X509v3 Subject Key Identifier:
//	        CA:74:4D:0E:F1:80:03:8A:9A:0D:14:7A:5F:F2:8A:1F:0C:48:D9:62
//
// Signature Algorithm: sha256WithRSAEncryption
// Signature Value:
func TestCreateCertificate(t *testing.T) {
	// create an RSA private caKey
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// create certificate for signing other certs, we need to do a round-trip
	// through DER encoding to sign the certificate.
	caSerialNumber := big.NewInt(0xDEADBEEF)
	caCert := &x509.Certificate{
		SerialNumber: caSerialNumber,
		Subject: pkix.Name{
			Organization: []string{"cluster.local"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	caCert, err = x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	s := Server{
		caCert:    caCert,
		caKey:     caKey,
		caCertPEM: string(caCertPEM),
		epManager: &fakeEndpointManager{
			MockEndpointManager: testendpointmanager.NewMockEndpointManager(),
			getEndpointsByServiceAccount: func(namespace, serviceAccount string) []*endpoint.Endpoint {
				return []*endpoint.Endpoint{{}}
			},
		},
		log: slog.Default(),
	}

	// we'll generate a CSR using the simple CSR we see in a default ztunnel
	// deployment:
	//         Version: 0 (0x0)
	//     Subject:
	//     Subject Public Key Info:
	//         Public Key Algorithm: id-ecPublicKey
	//             Public-Key: (256 bit)
	//             pub:
	//             ASN1 OID: prime256v1
	//             NIST CURVE: P-256
	//     Attributes:
	//     Requested Extensions:
	//         X509v3 Subject Alternative Name: critical
	//             URI:spiffe:///ns/kube-system/sa/default
	// Signature Algorithm: ecdsa-with-SHA256
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	uriSAN, err := url.Parse("spiffe:///ns/kube-system/sa/default")
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	csr := x509.CertificateRequest{
		Subject:            pkix.Name{},
		URIs:               []*url.URL{uriSAN},
		PublicKey:          clientKey.PublicKey,
		PublicKeyAlgorithm: x509.ECDSA,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csr, clientKey)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	istioCSR := &pb.IstioCertificateRequest{
		Csr: string(csrPEM),
	}

	istioCertResp, err := s.CreateCertificate(t.Context(), istioCSR)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	if len(istioCertResp.CertChain) != 2 {
		t.Fatalf("expected 2 certificates in the chain, got %d", len(istioCertResp.CertChain))
	}

	// client certificate must be first per ztunnel's parsing rules
	clientCertPEM := istioCertResp.CertChain[0]
	clientCertBlock, _ := pem.Decode([]byte(clientCertPEM))
	if clientCertBlock == nil || clientCertBlock.Type != "CERTIFICATE" {
		t.Fatalf("failed to decode client certificate PEM")
	}
	clientCert, err := x509.ParseCertificate(clientCertBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse client certificate: %v", err)
	}

	// trust anchor must be last per ztunnel's parsing rules.
	rootCertPEM := istioCertResp.CertChain[1]
	rootCertBlock, _ := pem.Decode([]byte(rootCertPEM))
	if rootCertBlock == nil || rootCertBlock.Type != "CERTIFICATE" {
		t.Fatalf("failed to decode root certificate PEM")
	}
	rootCert, err := x509.ParseCertificate(rootCertBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse root certificate: %v", err)
	}

	// validate client certificate's signature
	if err := clientCert.CheckSignatureFrom(rootCert); err != nil {
		t.Fatalf("client certificate signature validation failed: %v", err)
	}
	// validate client cert's public key algo
	if clientCert.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("expected client certificate public key algorithm to be ECDSA, got %v", clientCert.PublicKeyAlgorithm)
	}
	// validate client's URI SAN
	if len(clientCert.URIs) != 1 || clientCert.URIs[0].String() != uriSAN.String() {
		t.Fatalf("expected client certificate to have URI SAN %s, got %s", uriSAN.String(), clientCert.URIs[0].String())
	}

	// we create the CA certificate, so lets just ensure we see the same
	// certificate serial number, this is enough to know we served the cert
	// we created above as the root
	if rootCert.SerialNumber.Cmp(caSerialNumber) != 0 {
		t.Fatalf("expected root certificate serial number to be %s, got %s", caSerialNumber, rootCert.SerialNumber)
	}
}

// newTestServer returns a Server backed by a freshly generated RSA CA whose
// endpoint manager reports an endpoint for every namespace and service
// account.
func newTestServer(t *testing.T) *Server {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"cluster.local"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	return &Server{
		caCert:    caCert,
		caKey:     caKey,
		caCertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})),
		epManager: &fakeEndpointManager{
			MockEndpointManager: testendpointmanager.NewMockEndpointManager(),
			getEndpointsByServiceAccount: func(namespace, serviceAccount string) []*endpoint.Endpoint {
				return []*endpoint.Endpoint{{}}
			},
		},
		log: slog.Default(),
	}
}

// csrPEM signs the given request template with a fresh ECDSA key and returns
// it PEM encoded.
func csrPEM(t *testing.T, template *x509.CertificateRequest) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// TestCreateCertificateOnlyIssuesURISAN checks that the subject and the
// DNS, IP and email SANs requested in the CSR are not copied into the issued
// certificate. Only the URI SAN is checked against the endpoints on the node,
// so a client must not be able to obtain a certificate that is also valid for
// an arbitrary hostname.
func TestCreateCertificateOnlyIssuesURISAN(t *testing.T) {
	s := newTestServer(t)

	uriSAN, err := url.Parse("spiffe://cluster.local/ns/default/sa/default")
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}
	csr := csrPEM(t, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "kubernetes.default.svc"},
		URIs:           []*url.URL{uriSAN},
		DNSNames:       []string{"kubernetes.default.svc"},
		IPAddresses:    []net.IP{net.ParseIP("10.96.0.1")},
		EmailAddresses: []string{"admin@example.com"},
	})

	resp, err := s.CreateCertificate(t.Context(), &pb.IstioCertificateRequest{Csr: csr})
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	block, _ := pem.Decode([]byte(resp.CertChain[0]))
	if block == nil {
		t.Fatalf("failed to decode client certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse client certificate: %v", err)
	}

	if len(cert.URIs) != 1 || cert.URIs[0].String() != uriSAN.String() {
		t.Fatalf("expected client certificate to have URI SAN %s, got %v", uriSAN, cert.URIs)
	}
	if cert.Subject.CommonName != "" {
		t.Fatalf("expected empty subject, got %q", cert.Subject)
	}
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 {
		t.Fatalf("expected no DNS, IP or email SANs, got %v %v %v", cert.DNSNames, cert.IPAddresses, cert.EmailAddresses)
	}

	roots := x509.NewCertPool()
	roots.AddCert(s.caCert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "kubernetes.default.svc"}); err == nil {
		t.Fatalf("client certificate must not verify for a hostname")
	}
}

// TestCreateCertificateRejectsInvalidCSR checks that malformed CSRs and
// SPIFFE paths that do not follow /ns/<namespace>/sa/<service-account> are
// rejected before any endpoint lookup.
func TestCreateCertificateRejectsInvalidCSR(t *testing.T) {
	s := newTestServer(t)
	s.epManager.(*fakeEndpointManager).getEndpointsByServiceAccount = func(namespace, serviceAccount string) []*endpoint.Endpoint {
		t.Fatalf("unexpected endpoint lookup for namespace %q service account %q", namespace, serviceAccount)
		return nil
	}

	csrForPath := func(path string) string {
		uriSAN, err := url.Parse("spiffe://cluster.local" + path)
		if err != nil {
			t.Fatalf("failed to parse URI: %v", err)
		}
		return csrPEM(t, &x509.CertificateRequest{URIs: []*url.URL{uriSAN}})
	}

	for name, csr := range map[string]string{
		"not PEM":               "not a certificate request",
		"wrong segment names":   csrForPath("/foo/default/bar/default"),
		"empty namespace":       csrForPath("/ns//sa/default"),
		"empty service account": csrForPath("/ns/default/sa/"),
		"too many segments":     csrForPath("/ns/default/sa/default/extra"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.CreateCertificate(t.Context(), &pb.IstioCertificateRequest{Csr: csr}); err == nil {
				t.Fatalf("expected CSR to be rejected")
			}
		})
	}
}
