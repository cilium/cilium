/*
 * ZLint Copyright 2017 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package lints

import (
	"encoding/asn1"
	"unicode/utf8"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type subjectDNNotPrintableCharacters struct{}

func (l *subjectDNNotPrintableCharacters) Initialize() error {
	return nil
}

func (l *subjectDNNotPrintableCharacters) CheckApplies(c *x509.Certificate) bool {
	return true
}

func (l *subjectDNNotPrintableCharacters) Execute(c *x509.Certificate) *LintResult {
	rdnSequence := util.RawRDNSequence{}
	rest, err := asn1.Unmarshal(c.RawSubject, &rdnSequence)
	if err != nil {
		return &LintResult{Status: Fatal}
	}
	if len(rest) > 0 {
		return &LintResult{Status: Fatal}
	}

	for _, attrTypeAndValueSet := range rdnSequence {
		for _, attrTypeAndValue := range attrTypeAndValueSet {
			bytes := attrTypeAndValue.Value.Bytes
			for len(bytes) > 0 {
				r, size := utf8.DecodeRune(bytes)
				if r < 0x20 {
					return &LintResult{Status: Error}
				}
				if r >= 0x7F && r <= 0x9F {
					return &LintResult{Status: Error}
				}
				bytes = bytes[size:]
			}
		}
	}

	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_subject_dn_not_printable_characters",
		Description:   "X520 Subject fields MUST only contain printable control characters",
		Citation:      "RFC 5280: Appendix A",
		Source:        RFC5280,
		EffectiveDate: util.ZeroDate,
		Lint:          &subjectDNNotPrintableCharacters{},
	})
}
