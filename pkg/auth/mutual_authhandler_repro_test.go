// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
)

func Test_mutualAuthHandler_verifyPeerCertificate_Repro(t *testing.T) {
	certMap, keyMap, caPool := generateTestCertificates(t)

	// cert1000 is our "Attacker" certificate
	cert1000 := certMap["spiffe://spiffe.cilium/identity/1000"]
	// cert1001 is the "Target" certificate
	cert1001 := certMap["spiffe://spiffe.cilium/identity/1001"]

	m := &mutualAuthHandler{
		cfg:  MutualAuthConfig{MutualAuthListenerPort: 1234},
		log:  hivetest.Logger(t),
		cert: &fakeCertificateProvider{certMap: certMap, caPool: caPool, privkeyMap: keyMap},
	}

	// 1. Verify that single certificate chain works as expected
	singleChain := []*x509.Certificate{cert1000}
	_, err := m.verifyPeerCertificate(&id1000, caPool, [][]*x509.Certificate{singleChain})
	if err != nil {
		t.Fatalf("Expected valid single certificate chain to succeed, got: %v", err)
	}

	// 2. Verify that additional non-CA certificate in chain is rejected
	invalidChain := []*x509.Certificate{cert1000, cert1001}
	_, err = m.verifyPeerCertificate(&id1001, caPool, [][]*x509.Certificate{invalidChain})
	if err == nil {
		t.Fatalf("Expected chain with additional non-CA certificate to be rejected, but it succeeded")
	}
	if !strings.Contains(err.Error(), "found additional non-CA certificate in chain") {
		t.Fatalf("Expected error 'found additional non-CA certificate in chain', got: %v", err)
	}

	t.Log("Reproduction and verification test passed: Certificate substitution is successfully blocked")
}
