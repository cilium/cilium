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
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type SANDNSTooLong struct{}

func (l *SANDNSTooLong) Initialize() error {
	return nil
}

func (l *SANDNSTooLong) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.SubjectAlternateNameOID) && len(c.DNSNames) > 0
}

func (l *SANDNSTooLong) Execute(c *x509.Certificate) *LintResult {
	for _, dns := range c.DNSNames {
		if len(dns) > 253 {
			return &LintResult{Status: Error}
		}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ext_san_dns_name_too_long",
		Description:   "DNSName must be less than or equal to 253 bytes",
		Citation:      "RFC 5280",
		Source:        RFC5280,
		EffectiveDate: util.RFC5280Date,
		Lint:          &SANDNSTooLong{},
	})
}
