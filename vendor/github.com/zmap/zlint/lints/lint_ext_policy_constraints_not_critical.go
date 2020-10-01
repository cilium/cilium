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
RFC 5280: 4.2.1.11
Conforming CAs MUST mark this extension as critical.
************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type policyConstraintsCritical struct{}

func (l *policyConstraintsCritical) Initialize() error {
	return nil
}

func (l *policyConstraintsCritical) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.PolicyConstOID)
}

func (l *policyConstraintsCritical) Execute(c *x509.Certificate) *LintResult {
	pc := util.GetExtFromCert(c, util.PolicyConstOID)
	if !pc.Critical {
		return &LintResult{Status: Error}
	} else {
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ext_policy_constraints_not_critical",
		Description:   "Conforming CAs MUST mark the policy constraints extension as critical",
		Citation:      "RFC 5280: 4.2.1.11",
		Source:        RFC5280,
		EffectiveDate: util.RFC5280Date,
		Lint:          &policyConstraintsCritical{},
	})
}
