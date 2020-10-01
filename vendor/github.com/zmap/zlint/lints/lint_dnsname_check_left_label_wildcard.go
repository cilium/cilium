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
)

type DNSNameLeftLabelWildcardCheck struct{}

func (l *DNSNameLeftLabelWildcardCheck) Initialize() error {
	return nil
}

func (l *DNSNameLeftLabelWildcardCheck) CheckApplies(c *x509.Certificate) bool {
	return true
}

func wildcardInLeftLabelIncorrect(domain string) bool {
	labels := strings.Split(domain, ".")
	if len(labels) >= 1 {
		leftLabel := labels[0]
		if strings.Contains(leftLabel, "*") && leftLabel != "*" {
			return true
		}
	}
	return false
}

func (l *DNSNameLeftLabelWildcardCheck) Execute(c *x509.Certificate) *LintResult {
	if wildcardInLeftLabelIncorrect(c.Subject.CommonName) {
		return &LintResult{Status: Error}
	}
	for _, dns := range c.DNSNames {
		if wildcardInLeftLabelIncorrect(dns) {
			return &LintResult{Status: Error}
		}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_dnsname_left_label_wildcard_correct",
		Description:   "Wildcards in the left label of DNSName should only be *",
		Citation:      "BRs: 7.1.4.2",
		Source:        CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          &DNSNameLeftLabelWildcardCheck{},
	})
}
