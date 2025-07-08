// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"log/slog"
	"math/big"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"istio.io/api/security/v1alpha1"

	"github.com/cilium/cilium/api/v1/models"
	endpointapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/endpoint"
)

// mockEndpointsLookup is a mock implementation of EndpointsLookup for testing.
type mockEndpointsLookup struct{}

func (m *mockEndpointsLookup) GetEndpointsByServiceAccount(namespace string, serviceAccount string) []*endpoint.Endpoint {
	return []*endpoint.Endpoint{
		{},
	}
}

// The following methods are not implemented for this mock.
func (m *mockEndpointsLookup) Lookup(id string) (*endpoint.Endpoint, error) { panic("not implemented") }
func (m *mockEndpointsLookup) LookupCiliumID(id uint16) *endpoint.Endpoint  { panic("not implemented") }
func (m *mockEndpointsLookup) LookupCNIAttachmentID(id string) *endpoint.Endpoint {
	panic("not implemented")
}
func (m *mockEndpointsLookup) LookupIPv4(ipv4 string) *endpoint.Endpoint    { panic("not implemented") }
func (m *mockEndpointsLookup) LookupIPv6(ipv6 string) *endpoint.Endpoint    { panic("not implemented") }
func (m *mockEndpointsLookup) LookupIP(ip netip.Addr) *endpoint.Endpoint    { panic("not implemented") }
func (m *mockEndpointsLookup) LookupCEPName(name string) *endpoint.Endpoint { panic("not implemented") }
func (m *mockEndpointsLookup) GetEndpointsByPodName(name string) []*endpoint.Endpoint {
	panic("not implemented")
}
func (m *mockEndpointsLookup) GetEndpointsByContainerID(containerID string) []*endpoint.Endpoint {
	panic("not implemented")
}
func (m *mockEndpointsLookup) GetEndpoints() []*endpoint.Endpoint { panic("not implemented") }
func (m *mockEndpointsLookup) GetEndpointList(params endpointapi.GetEndpointParams) []*models.Endpoint {
	panic("not implemented")
}
func (m *mockEndpointsLookup) EndpointExists(id uint16) bool          { panic("not implemented") }
func (m *mockEndpointsLookup) GetHostEndpoint() *endpoint.Endpoint    { panic("not implemented") }
func (m *mockEndpointsLookup) HostEndpointExists() bool               { panic("not implemented") }
func (m *mockEndpointsLookup) GetIngressEndpoint() *endpoint.Endpoint { panic("not implemented") }
func (m *mockEndpointsLookup) IngressEndpointExists() bool            { panic("not implemented") }

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
		epLookup:  &mockEndpointsLookup{},
		log:       slog.Default().With("component", "xds_server_test"),
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

	istioCSR := &v1alpha1.IstioCertificateRequest{
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
	log.Printf("%s\n", rootCertBlock.Type)
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
