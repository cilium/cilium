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

/********************************************************************************************************************
BRs: 7.1.6.4
Subscriber Certificates
A Certificate issued to a Subscriber MUST contain one or more policy identifier(s), defined by the Issuing CA, in
the Certificate’s certificatePolicies extension that indicates adherence to and complIANce with these Requirements.
CAs complying with these Requirements MAY also assert one of the reserved policy OIDs in such Certificates.
*********************************************************************************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type subCertPolicyEmpty struct{}

func (l *subCertPolicyEmpty) Initialize() error {
	return nil
}

func (l *subCertPolicyEmpty) CheckApplies(c *x509.Certificate) bool {
	return !util.IsCACert(c)
}

func (l *subCertPolicyEmpty) Execute(c *x509.Certificate) *LintResult {
	// Add actual lint here
	if util.IsExtInCert(c, util.CertPolicyOID) && c.PolicyIdentifiers != nil {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_cert_policy_empty",
		Description:   "Subscriber certificates must contain at least one policy identifier that indicates adherence to CAB standards",
		Citation:      "BRs: 7.1.6.4",
		Source:        CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          &subCertPolicyEmpty{},
	})
}
