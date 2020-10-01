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
RFC 5280: 4.1.2.6
The subject field identifies the entity associated with the public
   key stored in the subject public key field.  The subject name MAY be
   carried in the subject field and/or the subjectAltName extension.  If
   the subject is a CA (e.g., the basic constraints extension, as
   discussed in Section 4.2.1.9, is present and the value of cA is
   TRUE), then the subject field MUST be populated with a non-empty
   distinguished name matching the contents of the issuer field (Section
   4.1.2.4) in all certificates issued by the subject CA.
************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type caSubjectEmpty struct{}

func (l *caSubjectEmpty) Initialize() error {
	return nil
}

func (l *caSubjectEmpty) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA
}

func (l *caSubjectEmpty) Execute(c *x509.Certificate) *LintResult {
	if &c.Subject != nil && util.NotAllNameFieldsAreEmpty(&c.Subject) {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ca_subject_field_empty",
		Description:   "CA Certificates subject field MUST not be empty and MUST have a non-empty distingushed name",
		Citation:      "RFC 5280: 4.1.2.6",
		Source:        RFC5280,
		EffectiveDate: util.RFC2459Date,
		Lint:          &caSubjectEmpty{},
	})
}
