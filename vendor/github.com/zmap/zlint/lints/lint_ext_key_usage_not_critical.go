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

// "When present, conforming CAs SHOULD mark this extension as critical."

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type checkKeyUsageCritical struct{}

func (l *checkKeyUsageCritical) Initialize() error {
	return nil
}

func (l *checkKeyUsageCritical) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.KeyUsageOID)
}

func (l *checkKeyUsageCritical) Execute(c *x509.Certificate) *LintResult {
	// Add actual lint here
	keyUsage := util.GetExtFromCert(c, util.KeyUsageOID)
	if keyUsage == nil {
		return &LintResult{Status: NA}
	}
	if keyUsage.Critical {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Warn}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "w_ext_key_usage_not_critical",
		Description:   "The keyUsage extension SHOULD be critical",
		Citation:      "RFC 5280: 4.2.1.3",
		Source:        RFC5280,
		EffectiveDate: util.RFC2459Date,
		Lint:          &checkKeyUsageCritical{},
	})
}
