package cabf_br

/*
 * ZLint Copyright 2020 Regents of the University of Michigan
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

/************************************************
BRs: 7.1.4.2.1
Also as of the Effective Date, the CA SHALL NOT
issue a certificate with an Expiry Date later than
1 November 2015 with a subjectAlternativeName extension
or Subject commonName field containing a Reserved IP
Address or Internal Name.
************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type SANReservedIP struct{}

func (l *SANReservedIP) Initialize() error {
	return nil
}

func (l *SANReservedIP) CheckApplies(c *x509.Certificate) bool {
	return c.NotAfter.After(util.NoReservedIP)
}

func (l *SANReservedIP) Execute(c *x509.Certificate) *lint.LintResult {
	for _, ip := range c.IPAddresses {
		if util.IsIANAReserved(ip) {
			return &lint.LintResult{Status: lint.Error}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_ext_san_contains_reserved_ip",
		Description:   "Effective October 1, 2016, CAs must revoke all unexpired certificates that contains a reserved IP or internal name.",
		Citation:      "BRs: 7.1.4.2.1",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          &SANReservedIP{},
	})
}
