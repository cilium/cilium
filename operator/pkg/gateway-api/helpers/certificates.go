// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import "encoding/pem"

// IsValidPemFormat checks if the given byte array contains at least one valid PEM
// formatted object, either certificate or key.
// This function is not intended to be used for validating the actual
// content of the PEM block.
func IsValidPemFormat(b []byte) bool {
	if len(b) == 0 {
		return false
	}

	p, rest := pem.Decode(b)
	if p == nil {
		return false
	}
	if len(rest) == 0 {
		return true
	}

	// We don't check the value of `rest` because
	// Envoy will be able to parse the file as long as there
	// is at least one valid certificate.
	return true
}
