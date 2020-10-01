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
ITU-T X.520 (02/2001) UpperBounds
ub-street-address INTEGER ::= 128

************************************************/

import (
	"unicode/utf8"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type subjectStreetAddressMaxLength struct{}

func (l *subjectStreetAddressMaxLength) Initialize() error {
	return nil
}

func (l *subjectStreetAddressMaxLength) CheckApplies(c *x509.Certificate) bool {
	return true
}

func (l *subjectStreetAddressMaxLength) Execute(c *x509.Certificate) *LintResult {
	for _, j := range c.Subject.StreetAddress {
		if utf8.RuneCountInString(j) > 128 {
			return &LintResult{Status: Error}
		}
	}

	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_subject_street_address_max_length",
		Description:   "The 'StreetAddress' field of the subject MUST be less than 129 characters",
		Citation:      "ITU-T X.520 (02/2001) UpperBounds",
		Source:        RFC5280,
		EffectiveDate: util.RFC2459Date,
		Lint:          &subjectStreetAddressMaxLength{},
	})
}
