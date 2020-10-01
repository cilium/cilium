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

/*************************************************************************
 RFC 5280: 4.1.2.6
 Where it is non-empty, the subject field MUST contain an X.500
   distinguished name (DN). The DN MUST be unique for each subject
   entity certified by the one CA as defined by the issuer name field. A
   CA may issue more than one certificate with the same DN to the same
   subject entity.
*************************************************************************/

import (
	"reflect"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/util"
)

type subjectDN struct{}

func (l *subjectDN) Initialize() error {
	return nil
}

func (l *subjectDN) CheckApplies(c *x509.Certificate) bool {
	return true
}

func (l *subjectDN) Execute(c *x509.Certificate) *LintResult {
	if reflect.TypeOf(c.Subject) != reflect.TypeOf(*(new(pkix.Name))) {
		return &LintResult{Status: Error}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_subject_not_dn",
		Description:   "When not empty, the subject field MUST be a distinguished name",
		Citation:      "RFC 5280: 4.1.2.6",
		Source:        RFC5280,
		EffectiveDate: util.RFC2459Date,
		Lint:          &subjectDN{},
	})
}
