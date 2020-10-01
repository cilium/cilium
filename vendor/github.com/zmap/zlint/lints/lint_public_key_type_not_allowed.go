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

type publicKeyAllowed struct{}

func (l *publicKeyAllowed) Initialize() error {
	return nil
}

func (l *publicKeyAllowed) CheckApplies(c *x509.Certificate) bool {
	return true
}

func (l *publicKeyAllowed) Execute(c *x509.Certificate) *LintResult {
	alg := c.PublicKeyAlgorithm
	if alg != x509.UnknownPublicKeyAlgorithm {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_public_key_type_not_allowed",
		Description:   "Certificates MUST have RSA, DSA, or ECDSA public key type",
		Citation:      "BRs: 6.1.5",
		Source:        CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          &publicKeyAllowed{},
	})
}
