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

/************************************************
Change this to match source TEXT
************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type SubCANameConstraintsNotCritical struct{}

func (l *SubCANameConstraintsNotCritical) Initialize() error {
	return nil
}

func (l *SubCANameConstraintsNotCritical) CheckApplies(cert *x509.Certificate) bool {
	return util.IsSubCA(cert) && util.IsExtInCert(cert, util.NameConstOID)
}

func (l *SubCANameConstraintsNotCritical) Execute(cert *x509.Certificate) *LintResult {
	if ski := util.GetExtFromCert(cert, util.NameConstOID); ski.Critical {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Warn}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "w_sub_ca_name_constraints_not_critical",
		Description:   "Subordinate CA Certificate: NameConstraints if present, SHOULD be marked critical.",
		Citation:      "BRs: 7.1.2.2",
		Source:        CABFBaselineRequirements,
		EffectiveDate: util.CABV102Date,
		Lint:          &SubCANameConstraintsNotCritical{},
	})
}
