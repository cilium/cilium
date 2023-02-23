// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spire

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// This file implements the CertificateProvider interface

func (s *SpireDelegateClient) GetTrustBundle() (*x509.CertPool, error) {
	if s.trustBundle == nil {
		return nil, errors.New("trust bundle not yet available")
	}
	return s.trustBundle, nil
}

func (s *SpireDelegateClient) GetCertificateForIdentity(identity string) (*tls.Certificate, error) {
	spiffeID := s.sniToSPIFFEID(identity)
	svid, ok := s.svidStore[spiffeID]
	if !ok {
		return nil, fmt.Errorf("no SPIFFE ID for %s", spiffeID)
	}

	if len(svid.X509Svid.CertChain) == 0 {
		return nil, fmt.Errorf("no certificate chain inside %s", spiffeID)
	}

	var leafCert *x509.Certificate
	for _, cert := range svid.X509Svid.CertChain {
		cert, err := x509.ParseCertificate(cert)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		if !cert.IsCA {
			leafCert = cert
			break
		}
	}
	if leafCert == nil {
		return nil, fmt.Errorf("no leaf certificate inside %s", spiffeID)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(svid.X509SvidKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private keyof %s: %w", spiffeID, err)
	}

	return &tls.Certificate{
		Certificate: svid.X509Svid.CertChain,
		PrivateKey:  privKey,
		Leaf:        leafCert,
	}, nil
}

func (s *SpireDelegateClient) sniToSPIFFEID(sni string) string {
	return fmt.Sprintf("spiffe://%s/cilium-id/%s", s.cfg.SpiffeTrustDomain, sni)
}

func (s *SpireDelegateClient) ValidateIdentity(identity string, cert *x509.Certificate) (bool, error) {
	spiffeID := s.sniToSPIFFEID(identity)

	// Spec: SVIDs containing more than one URI SAN MUST be rejected
	if len(cert.URIs) != 1 {
		return false, errors.New("SPIFFE IDs must have exactly one URI SAN")
	}

	return cert.URIs[0].String() == spiffeID, nil
}
