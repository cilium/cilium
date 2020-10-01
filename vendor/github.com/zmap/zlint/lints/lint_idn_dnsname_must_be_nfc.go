package lints

/*
 * ZLint Copyright 2018 Regents of the University of Michigan
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

import (
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

type IDNNotNFC struct{}

func (l *IDNNotNFC) Initialize() error {
	return nil
}

func (l *IDNNotNFC) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.SubjectAlternateNameOID)
}

func (l *IDNNotNFC) Execute(c *x509.Certificate) *LintResult {
	for _, dns := range c.DNSNames {
		labels := strings.Split(dns, ".")
		for _, label := range labels {
			if strings.HasPrefix(label, "xn--") {
				unicodeLabel, err := idna.ToUnicode(label)
				if err != nil {
					return &LintResult{Status: NA}
				}
				if !norm.NFC.IsNormalString(unicodeLabel) {
					return &LintResult{Status: Error}
				}
			}
		}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_international_dns_name_not_nfc",
		Description:   "Internationalized DNSNames must be normalized by unicode normalization form C",
		Citation:      "RFC 8399",
		Source:        RFC5891,
		EffectiveDate: util.RFC8399Date,
		Lint:          &IDNNotNFC{},
	})
}
