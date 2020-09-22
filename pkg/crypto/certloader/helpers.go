// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
