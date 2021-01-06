package rfc

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

/************************************************
"A certificate MUST NOT include more than one instance of a particular extension."
************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v2/lint"
	"github.com/zmap/zlint/v2/util"
)

type ExtDuplicateExtension struct{}

func (l *ExtDuplicateExtension) Initialize() error {
	return nil
}

func (l *ExtDuplicateExtension) CheckApplies(cert *x509.Certificate) bool {
	return cert.Version == 3
}

func (l *ExtDuplicateExtension) Execute(cert *x509.Certificate) *lint.LintResult {
	// O(n^2) is not terrible here because n is capped around 10
	for i := 0; i < len(cert.Extensions); i++ {
		for j := i + 1; j < len(cert.Extensions); j++ {
			if i != j && cert.Extensions[i].Id.Equal(cert.Extensions[j].Id) {
				return &lint.LintResult{Status: lint.Error}
			}
		}
	}
	// Nested loop will return if it finds a duplicate, so safe to assume pass
	return &lint.LintResult{Status: lint.Pass}
}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_ext_duplicate_extension",
		Description:   "A certificate MUST NOT include more than one instance of a particular extension",
		Citation:      "RFC 5280: 4.2",
		Source:        lint.RFC5280,
		EffectiveDate: util.RFC2459Date,
		Lint:          &ExtDuplicateExtension{},
	})
}
