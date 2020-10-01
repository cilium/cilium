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

/*********************************************************
RFC 5280: 4.2.1.1
Conforming CAs MUST mark this extension as non-critical.
**********************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type authorityKeyIdCritical struct{}

func (l *authorityKeyIdCritical) Initialize() error {
	return nil
}

func (l *authorityKeyIdCritical) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.AuthkeyOID)
}

func (l *authorityKeyIdCritical) Execute(c *x509.Certificate) *LintResult {
	aki := util.GetExtFromCert(c, util.AuthkeyOID) //pointer to the extension
	if aki.Critical {
		return &LintResult{Status: Error}
	} else { //implies !aki.Critical
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ext_authority_key_identifier_critical",
		Description:   "The authority key identifier extension must be non-critical",
		Citation:      "RFC 5280: 4.2.1.1",
		Source:        RFC5280,
		EffectiveDate: util.RFC2459Date,
		Lint:          &authorityKeyIdCritical{},
	})
}
