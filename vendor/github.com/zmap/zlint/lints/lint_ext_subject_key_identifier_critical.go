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

/**********************************************************
RFC 5280: 4.2.1.2
 Conforming CAs MUST mark this extension as non-critical.
**********************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type subjectKeyIdCritical struct{}

func (l *subjectKeyIdCritical) Initialize() error {
	return nil
}

func (l *subjectKeyIdCritical) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.SubjectKeyIdentityOID)
}

func (l *subjectKeyIdCritical) Execute(c *x509.Certificate) *LintResult {
	ski := util.GetExtFromCert(c, util.SubjectKeyIdentityOID) //pointer to the extension
	if ski.Critical {
		return &LintResult{Status: Error}
	} else { //implies !ski.Critical
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ext_subject_key_identifier_critical",
		Description:   "The subject key identifier extension MUST be non-critical",
		Citation:      "RFC 5280: 4.2.1.2",
		Source:        RFC5280,
		EffectiveDate: util.RFC2459Date,
		Lint:          &subjectKeyIdCritical{},
	})
}
