package x509svid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"

	"github.com/spiffe/go-spiffe/v2/internal/pemutil"
	"github.com/spiffe/go-spiffe/v2/internal/x509util"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/zeebo/errs"
)

// SVID represents a SPIFFE X509-SVID.
type SVID struct {
	// ID is the SPIFFE ID of the X509-SVID.
	ID spiffeid.ID

	// Certificates are the X.509 certificates of the X509-SVID. The leaf
	// certificate is the X509-SVID certificate. Any remaining certificates (
	// if any) chain the X509-SVID certificate back to a X.509 root for the
	// trust domain.
	Certificates []*x509.Certificate

	// PrivateKey is the private key for the X509-SVID.
	PrivateKey crypto.Signer
}

// Load loads the X509-SVID from PEM encoded files on disk. certFile and
// keyFile may be the same file.
func Load(certFile, keyFile string) (*SVID, error) {
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, x509svidErr.New("cannot read certificate file: %w", err)
	}

	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, x509svidErr.New("cannot read key file: %w", err)
	}

	return Parse(certBytes, keyBytes)
}

// Parse parses the X509-SVID from PEM blocks containing certificate and key
// bytes. The certificate must be one or more PEM blocks with ASN.1 DER. The
// key must be a PEM block with PKCS#8 ASN.1 DER.
func Parse(certBytes, keyBytes []byte) (*SVID, error) {
	certs, err := pemutil.ParseCertificates(certBytes)
	if err != nil {
		return nil, x509svidErr.New("cannot parse PEM encoded certificate: %v", err)
	}

	privateKey, err := pemutil.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, x509svidErr.New("cannot parse PEM encoded private key: %v", err)
	}

	return newSVID(certs, privateKey)
}

// ParseRaw parses the X509-SVID from certificate and key bytes. The
// certificate must be ASN.1 DER (concatenated with no intermediate
// padding if there are more than one certificate). The key must be a PKCS#8
// ASN.1 DER.
func ParseRaw(certBytes, keyBytes []byte) (*SVID, error) {
	certificates, err := x509.ParseCertificates(certBytes)
	if err != nil {
		return nil, x509svidErr.New("cannot parse DER encoded certificate: %v", err)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, x509svidErr.New("cannot parse DER encoded private key: %v", err)
	}

	return newSVID(certificates, privateKey)
}

// Marshal marshals the X509-SVID and returns PEM encoded blocks for the SVID
// and private key.
func (s *SVID) Marshal() ([]byte, []byte, error) {
	if len(s.Certificates) == 0 {
		return nil, nil, x509svidErr.New("no certificates to marshal")
	}
	certBytes := pemutil.EncodeCertificates(s.Certificates)
	keyBytes, err := pemutil.EncodePKCS8PrivateKey(s.PrivateKey)
	if err != nil {
		return nil, nil, x509svidErr.New("cannot encode private key: %v", err)
	}

	return certBytes, keyBytes, nil
}

// MarshalRaw marshals the X509-SVID and returns ASN.1 DER for the certificates
// (concatenated with no intermediate padding) and PKCS8 ASN1.DER for the
// private key.
func (s *SVID) MarshalRaw() ([]byte, []byte, error) {
	key, err := x509.MarshalPKCS8PrivateKey(s.PrivateKey)
	if err != nil {
		return nil, nil, x509svidErr.New("cannot marshal private key: %v", err)
	}

	if len(s.Certificates) == 0 {
		return nil, nil, x509svidErr.New("no certificates to marshal")
	}

	certs := x509util.ConcatRawCertsFromCerts(s.Certificates)
	return certs, key, nil
}

// GetX509SVID returns the X509-SVID. It implements the Source interface.
func (s *SVID) GetX509SVID() (*SVID, error) {
	return s, nil
}

func newSVID(certificates []*x509.Certificate, privateKey crypto.PrivateKey) (*SVID, error) {
	spiffeID, err := validateCertificates(certificates)
	if err != nil {
		return nil, x509svidErr.New("certificate validation failed: %v", err)
	}

	signer, err := validatePrivateKey(privateKey, certificates[0])
	if err != nil {
		return nil, x509svidErr.New("private key validation failed: %v", err)
	}

	return &SVID{
		Certificates: certificates,
		PrivateKey:   signer,
		ID:           *spiffeID,
	}, nil
}

// validate the slice of certificates constitutes a valid SVID chain according
// to the spiffe standard and returns the spiffe id of the leaf certificate
func validateCertificates(certificates []*x509.Certificate) (*spiffeid.ID, error) {
	if len(certificates) == 0 {
		return nil, errs.New("no certificates found")
	}

	leafID, err := validateLeafCertificate(certificates[0])
	if err != nil {
		return nil, err
	}

	err = validateSigningCertificates(certificates[1:])
	if err != nil {
		return nil, err
	}

	return leafID, nil
}

func validateLeafCertificate(leaf *x509.Certificate) (*spiffeid.ID, error) {
	leafID, err := IDFromCert(leaf)
	if err != nil {
		return nil, errs.New("cannot get leaf certificate SPIFFE ID: %v", err)
	}
	if leaf.IsCA {
		return nil, errs.New("leaf certificate must not have CA flag set to true")
	}

	err = validateKeyUsage(leaf)
	if err != nil {
		return nil, err
	}

	return &leafID, err
}

func validateSigningCertificates(signingCerts []*x509.Certificate) error {
	for _, cert := range signingCerts {
		if !cert.IsCA {
			return errs.New("signing certificate must have CA flag set to true")
		}
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return errs.New("signing certificate must have 'keyCertSign' set as key usage")
		}
	}

	return nil
}

func validateKeyUsage(leaf *x509.Certificate) error {
	switch {
	case leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0:
		return errs.New("leaf certificate must have 'digitalSignature' set as key usage")
	case leaf.KeyUsage&x509.KeyUsageCertSign > 0:
		return errs.New("leaf certificate must not have 'keyCertSign' set as key usage")
	case leaf.KeyUsage&x509.KeyUsageCRLSign > 0:
		return errs.New("leaf certificate must not have 'cRLSign' set as key usage")
	}
	return nil
}

func validatePrivateKey(privateKey crypto.PrivateKey, leaf *x509.Certificate) (crypto.Signer, error) {
	if privateKey == nil {
		return nil, errs.New("no private key found")
	}

	matched, err := keyMatches(privateKey, leaf.PublicKey)
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, errs.New("leaf certificate does not match private key")
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, errs.New("expected crypto.Signer; got %T", privateKey)
	}

	return signer, nil
}

func keyMatches(privateKey crypto.PrivateKey, publicKey crypto.PublicKey) (bool, error) {
	switch privateKey := privateKey.(type) {
	case *rsa.PrivateKey:
		rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
		return ok && rsaPublicKeyEqual(&privateKey.PublicKey, rsaPublicKey), nil
	case *ecdsa.PrivateKey:
		ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
		return ok && ecdsaPublicKeyEqual(&privateKey.PublicKey, ecdsaPublicKey), nil
	default:
		return false, errs.New("unsupported private key type %T", privateKey)
	}
}

func rsaPublicKeyEqual(a, b *rsa.PublicKey) bool {
	return a.E == b.E && a.N.Cmp(b.N) == 0
}

func ecdsaPublicKeyEqual(a, b *ecdsa.PublicKey) bool {
	return a.Curve == b.Curve && a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}
