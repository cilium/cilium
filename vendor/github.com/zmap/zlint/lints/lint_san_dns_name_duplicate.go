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
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type SANDNSDuplicate struct{}

func (l *SANDNSDuplicate) Initialize() error {
	return nil
}

func (l *SANDNSDuplicate) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.SubjectAlternateNameOID)
}

func (l *SANDNSDuplicate) Execute(c *x509.Certificate) *LintResult {
	checkedDNSNames := map[string]struct{}{}
	for _, dns := range c.DNSNames {
		normalizedDNSName := strings.ToLower(dns)
		if _, isPresent := checkedDNSNames[normalizedDNSName]; isPresent {
			return &LintResult{Status: Notice}
		}

		checkedDNSNames[normalizedDNSName] = struct{}{}
	}

	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "n_san_dns_name_duplicate",
		Description:   "SAN DNSName contains duplicate values",
		Citation:      "awslabs certlint",
		Source:        AWSLabs,
		EffectiveDate: util.ZeroDate,
		Lint:          &SANDNSDuplicate{},
	})
}
