package x509svid

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/x509util"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// VerifyOption is an option used when verifying X509-SVIDs.
type VerifyOption interface {
	apply(config *verifyConfig)
}

// WithTime sets the time used when verifying validity periods on the X509-SVID.
// If not used, the current time will be used.
func WithTime(now time.Time) VerifyOption {
	return verifyOption(func(config *verifyConfig) {
		config.now = now
	})
}

// Verify verifies an X509-SVID chain using the X.509 bundle source. It
// returns the SPIFFE ID of the X509-SVID and one or more chains back to a root
// in the bundle.
func Verify(certs []*x509.Certificate, bundleSource x509bundle.Source, opts ...VerifyOption) (spiffeid.ID, [][]*x509.Certificate, error) {
	config := &verifyConfig{}
	for _, opt := range opts {
		opt.apply(config)
	}

	switch {
	case len(certs) == 0:
		return spiffeid.ID{}, nil, wrapX509svidErr(errors.New("empty certificates chain"))
	case bundleSource == nil:
		return spiffeid.ID{}, nil, wrapX509svidErr(errors.New("bundleSource is required"))
	}

	leaf := certs[0]
	id, err := IDFromCert(leaf)
	if err != nil {
		return spiffeid.ID{}, nil, wrapX509svidErr(fmt.Errorf("could not get leaf SPIFFE ID: %w", err))
	}

	switch {
	case leaf.IsCA:
		return id, nil, wrapX509svidErr(errors.New("leaf certificate with CA flag set to true"))
	case leaf.KeyUsage&x509.KeyUsageCertSign > 0:
		return id, nil, wrapX509svidErr(errors.New("leaf certificate with KeyCertSign key usage"))
	case leaf.KeyUsage&x509.KeyUsageCRLSign > 0:
		return id, nil, wrapX509svidErr(errors.New("leaf certificate with KeyCrlSign key usage"))
	}

	bundle, err := bundleSource.GetX509BundleForTrustDomain(id.TrustDomain())
	if err != nil {
		return id, nil, wrapX509svidErr(fmt.Errorf("could not get X509 bundle: %w", err))
	}

	verifiedChains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         x509util.NewCertPool(bundle.X509Authorities()),
		Intermediates: x509util.NewCertPool(certs[1:]),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   config.now,
	})
	if err != nil {
		return id, nil, wrapX509svidErr(fmt.Errorf("could not verify leaf certificate: %w", err))
	}

	return id, verifiedChains, nil
}

// ParseAndVerify parses and verifies an X509-SVID chain using the X.509
// bundle source. It returns the SPIFFE ID of the X509-SVID and one or more
// chains back to a root in the bundle.
func ParseAndVerify(rawCerts [][]byte, bundleSource x509bundle.Source, opts ...VerifyOption) (spiffeid.ID, [][]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return spiffeid.ID{}, nil, wrapX509svidErr(fmt.Errorf("unable to parse certificate: %w", err))
		}
		certs = append(certs, cert)
	}
	return Verify(certs, bundleSource, opts...)
}

// IDFromCert extracts the SPIFFE ID from the URI SAN of the provided
// certificate. It will return an an error if the certificate does not have
// exactly one URI SAN with a well-formed SPIFFE ID.
func IDFromCert(cert *x509.Certificate) (spiffeid.ID, error) {
	switch {
	case len(cert.URIs) == 0:
		return spiffeid.ID{}, errors.New("certificate contains no URI SAN")
	case len(cert.URIs) > 1:
		return spiffeid.ID{}, errors.New("certificate contains more than one URI SAN")
	}
	return spiffeid.FromURI(cert.URIs[0])
}

type verifyConfig struct {
	now time.Time
}

type verifyOption func(config *verifyConfig)

func (fn verifyOption) apply(config *verifyConfig) {
	fn(config)
}

func wrapX509svidErr(err error) error {
	return fmt.Errorf("x509svid: %w", err)
}
