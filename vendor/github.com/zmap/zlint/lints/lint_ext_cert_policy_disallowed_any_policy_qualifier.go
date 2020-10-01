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

/*******************************************************************
RFC 5280: 4.2.1.4
To promote interoperability, this profile RECOMMENDS that policy
information terms consist of only an OID.  Where an OID alone is
insufficient, this profile strongly recommends that the use of
qualifiers be limited to those identified in this section.  When
qualifiers are used with the special policy anyPolicy, they MUST be
limited to the qualifiers identified in this section.  Only those
qualifiers returned as a result of path validation are considered.
********************************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type unrecommendedQualifier struct{}

func (l *unrecommendedQualifier) Initialize() error {
	return nil
}

func (l *unrecommendedQualifier) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.CertPolicyOID)
}

func (l *unrecommendedQualifier) Execute(c *x509.Certificate) *LintResult {
	for _, firstLvl := range c.QualifierId {
		for _, qualifierId := range firstLvl {
			if !qualifierId.Equal(util.CpsOID) && !qualifierId.Equal(util.UserNoticeOID) {
				return &LintResult{Status: Error}
			}
		}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ext_cert_policy_disallowed_any_policy_qualifier",
		Description:   "When qualifiers are used with the special policy anyPolicy, they must be limited to qualifiers identified in this section: (4.2.1.4)",
		Citation:      "RFC 5280: 4.2.1.4",
		Source:        RFC5280,
		EffectiveDate: util.RFC3280Date,
		Lint:          &unrecommendedQualifier{},
	})
}
