// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certs

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/cilium/cilium/pkg/identity"
)

type CertificateRotationEvent struct {
	Identity identity.NumericIdentity
}

type CertificateProvider interface {
	// GetTrustBundle gives the CA trust bundle for the certificate provider
	// this is then used to verify the certificates given by the peer in the handshake
	GetTrustBundle() (*x509.CertPool, error)

	// GetCertificateForIdentity gives the certificate and intermediates required
	// to send as trust chain for a certain identity as well as a private key
	GetCertificateForIdentity(id identity.NumericIdentity) (*tls.Certificate, error)

	// ValidateIdentity will check if the SANs or other identity methods are valid
	// for the given Cilium identity this function is needed as SPIFFE encodes the
	// full ID in the URI SAN.
	ValidateIdentity(id identity.NumericIdentity, cert *x509.Certificate) (bool, error)

	// NumericIdentityToSNI will return the SNI that should be used for a given Cilium Identity
	NumericIdentityToSNI(id identity.NumericIdentity) string

	// SNIToNumericIdentity will return the Cilium Identity for a given SNI
	SNIToNumericIdentity(sni string) (identity.NumericIdentity, error)

	// SubscribeToRotatedIdentities will return a channel with the identities that have rotated certificates
	SubscribeToRotatedIdentities() <-chan CertificateRotationEvent
}
