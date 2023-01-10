// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certloader

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
)

// keypairId returns a string representation of the given Certificate chain
// Serial Numbers.
func keypairId(crt *tls.Certificate) string {
	if crt == nil {
		return "<nil>"
	}

	sn := serialNumbers(crt.Certificate)
	return strings.Join(sn, ",")
}

// serialNumbers returns the given ASN1.DER encoded certificates Serial Number
// in hexadecimal format.
func serialNumbers(certificates [][]byte) []string {
	sn := make([]string, 0, len(certificates))
	for _, crt := range certificates {
		parsed, err := x509.ParseCertificate(crt)
		if err == nil {
			sn = append(sn, parsed.SerialNumber.Text(16))
		}
	}
	return sn
}
