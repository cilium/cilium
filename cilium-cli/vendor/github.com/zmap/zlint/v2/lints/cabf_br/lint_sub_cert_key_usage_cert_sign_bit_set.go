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

/**************************************************************************
BRs: 7.1.2.3
keyUsage (optional)
If present, bit positions for keyCertSign and cRLSign MUST NOT be set.
***************************************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v2/lint"
	"github.com/zmap/zlint/v2/util"
)

type subCertKeyUsageBitSet struct{}

func (l *subCertKeyUsageBitSet) Initialize() error {
	return nil
}

func (l *subCertKeyUsageBitSet) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.KeyUsageOID) && !util.IsCACert(c)
}

func (l *subCertKeyUsageBitSet) Execute(c *x509.Certificate) *lint.LintResult {
	if (c.KeyUsage & x509.KeyUsageCertSign) == x509.KeyUsageCertSign {
		return &lint.LintResult{Status: lint.Error}
	} else { //key usage doesn't allow cert signing or isn't present
		return &lint.LintResult{Status: lint.Pass}
	}
}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sub_cert_key_usage_cert_sign_bit_set",
		Description:   "Subscriber Certificate: keyUsage if present, bit positions for keyCertSign and cRLSign MUST NOT be set.",
		Citation:      "BRs: 7.1.2.3",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          &subCertKeyUsageBitSet{},
	})
}
