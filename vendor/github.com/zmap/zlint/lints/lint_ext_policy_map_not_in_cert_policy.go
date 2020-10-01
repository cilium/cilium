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

/*********************************************************************
RFC 5280: 4.2.1.5
Each issuerDomainPolicy named in the policy mapping extension SHOULD
   also be asserted in a certificate policies extension in the same
   certificate.  Policies SHOULD NOT be mapped either to or from the
   special value anyPolicy (section 4.2.1.5).
*********************************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type policyMapMatchesCertPolicy struct{}

func (l *policyMapMatchesCertPolicy) Initialize() error {
	return nil
}

func (l *policyMapMatchesCertPolicy) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.PolicyMapOID)
}

func (l *policyMapMatchesCertPolicy) Execute(c *x509.Certificate) *LintResult {
	extPolMap := util.GetExtFromCert(c, util.PolicyMapOID)
	polMap, err := util.GetMappedPolicies(extPolMap)
	if err != nil {
		return &LintResult{Status: Fatal}
	}
	for _, pair := range polMap {
		if !util.SliceContainsOID(c.PolicyIdentifiers, pair[0]) {
			return &LintResult{Status: Warn}
		}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "w_ext_policy_map_not_in_cert_policy",
		Description:   "Each issuerDomainPolicy named in the policy mappings extension should also be asserted in a certificate policies extension",
		Citation:      "RFC 5280: 4.2.1.5",
		Source:        RFC5280,
		EffectiveDate: util.RFC3280Date,
		Lint:          &policyMapMatchesCertPolicy{},
	})
}
