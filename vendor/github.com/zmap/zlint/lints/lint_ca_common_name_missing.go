package lints

/*
 * ZLint Copyright 2017 Regents of the University of Michigan
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

type caCommonNameMissing struct{}

func (l *caCommonNameMissing) Initialize() error {
	return nil
}

func (l *caCommonNameMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsCACert(c)
}

func (l *caCommonNameMissing) Execute(c *x509.Certificate) *LintResult {
	if c.Subject.CommonName == "" {
		return &LintResult{Status: Error}
	} else {
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ca_common_name_missing",
		Description:   "CA Certificates common name MUST be included.",
		Citation:      "BRs: 7.1.4.3.1",
		Source:        CABFBaselineRequirements,
		EffectiveDate: util.CABV148Date,
		Lint:          &caCommonNameMissing{},
	})
}
