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

/*If the Certificate asserts the policy identifier of 2.23.140.1.2.3, then it MUST also include (i) either organizationName or givenName and surname, (ii) localityName (to the extent such field is required under Section 7.1.4.2.2), (iii) stateOrProvinceName (to the extent required under Section 7.1.4.2.2), and (iv) countryName in the Subject field.*/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v2/lint"
	"github.com/zmap/zlint/v2/util"
)

type CertPolicyIVRequiresCountry struct{}

func (l *CertPolicyIVRequiresCountry) Initialize() error {
	return nil
}

func (l *CertPolicyIVRequiresCountry) CheckApplies(cert *x509.Certificate) bool {
	return util.SliceContainsOID(cert.PolicyIdentifiers, util.BRIndividualValidatedOID)
}

func (l *CertPolicyIVRequiresCountry) Execute(cert *x509.Certificate) *lint.LintResult {
	var out lint.LintResult
	if util.TypeInName(&cert.Subject, util.CountryNameOID) {
		out.Status = lint.Pass
	} else {
		out.Status = lint.Error
	}
	return &out
}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_cert_policy_iv_requires_country",
		Description:   "If certificate policy 2.23.140.1.2.3 is included, countryName MUST be included in subject",
		Citation:      "BRs: 7.1.6.1",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABV131Date,
		Lint:          &CertPolicyIVRequiresCountry{},
	})
}
