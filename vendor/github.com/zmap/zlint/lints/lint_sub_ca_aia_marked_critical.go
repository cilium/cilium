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

type subCaAIAMarkedCritical struct{}

func (l *subCaAIAMarkedCritical) Initialize() error {
	return nil
}

func (l *subCaAIAMarkedCritical) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubCA(c) && util.IsExtInCert(c, util.AiaOID)
}

func (l *subCaAIAMarkedCritical) Execute(c *x509.Certificate) *LintResult {
	e := util.GetExtFromCert(c, util.AiaOID)
	if e.Critical {
		return &LintResult{Status: Error}
	} else {
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_ca_aia_marked_critical",
		Description:   "Subordinate CA Certificate: authorityInformationAccess MUST NOT be marked critical",
		Citation:      "BRs: 7.1.2.2",
		Source:        CABFBaselineRequirements,
		EffectiveDate: util.ZeroDate,
		Lint:          &subCaAIAMarkedCritical{},
	})
}
