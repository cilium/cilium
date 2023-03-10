// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spire

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/auth/certs"
	"github.com/cilium/cilium/pkg/identity"
)

// This file implements the CertificateProvider interface

func (s *SpireDelegateClient) GetTrustBundle() (*x509.CertPool, error) {
	if s.trustBundle == nil {
		return nil, errors.New("trust bundle not yet available")
	}
	return s.trustBundle, nil
}

func (s *SpireDelegateClient) GetCertificateForIdentity(id identity.NumericIdentity) (*tls.Certificate, error) {
	spiffeID := s.sniToSPIFFEID(id)
	s.svidStoreMutex.RLock()
	svid, ok := s.svidStore[spiffeID]
	s.svidStoreMutex.RUnlock()
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

func (s *SpireDelegateClient) sniToSPIFFEID(id identity.NumericIdentity) string {
	return "spiffe://" + s.cfg.SpiffeTrustDomain + "/identity/" + id.String()
}

func (s *SpireDelegateClient) spiffeIDToNumericIdentity(spiffeID string) (identity.NumericIdentity, error) {
	prefix := "spiffe://" + s.cfg.SpiffeTrustDomain + "/identity/"
	if !strings.HasPrefix(spiffeID, prefix) {
		return 0, fmt.Errorf("SPIFFE ID %s does not belong to our trust domain or is not in the valid format", spiffeID)
	}

	idStr := strings.TrimPrefix(spiffeID, prefix)
	return identity.ParseNumericIdentity(idStr)
}

func (s *SpireDelegateClient) ValidateIdentity(id identity.NumericIdentity, cert *x509.Certificate) (bool, error) {
	spiffeID := s.sniToSPIFFEID(id)

	// Spec: SVIDs containing more than one URI SAN MUST be rejected
	if len(cert.URIs) != 1 {
		return false, errors.New("SPIFFE IDs must have exactly one URI SAN")
	}

	return cert.URIs[0].String() == spiffeID, nil
}

func (s *SpireDelegateClient) NumericIdentityToSNI(id identity.NumericIdentity) string {
	return id.String() + "." + s.cfg.SpiffeTrustDomain
}

func (s *SpireDelegateClient) SNIToNumericIdentity(sni string) (identity.NumericIdentity, error) {
	suffix := "." + s.cfg.SpiffeTrustDomain
	if !strings.HasSuffix(sni, suffix) {
		return 0, fmt.Errorf("SNI %s does not belong to our trust domain", sni)
	}

	idStr := strings.TrimSuffix(sni, suffix)
	return identity.ParseNumericIdentity(idStr)
}

func (s *SpireDelegateClient) SubscribeToRotatedIdentities() <-chan certs.CertificateRotationEvent {
	return s.rotatedIdentitiesChan
}
