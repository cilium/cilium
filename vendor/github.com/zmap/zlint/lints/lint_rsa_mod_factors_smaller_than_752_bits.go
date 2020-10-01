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

/**************************************************************************************************
6.1.6. Public Key Parameters Generation and Quality Checking
RSA: The CA SHALL confirm that the value of the public exponent is an odd number equal to 3 or more. Additionally, the public exponent SHOULD be in the range between 216+1 and 2256-1. The modulus SHOULD also have the following characteristics: an odd number, not the power of a prime, and have no factors smaller than 752. [Citation: Section 5.3.3, NIST SP 800‐89].
**************************************************************************************************/

import (
	"crypto/rsa"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type rsaModSmallFactor struct{}

func (l *rsaModSmallFactor) Initialize() error {
	return nil
}

func (l *rsaModSmallFactor) CheckApplies(c *x509.Certificate) bool {
	_, ok := c.PublicKey.(*rsa.PublicKey)
	return ok && c.PublicKeyAlgorithm == x509.RSA
}

func (l *rsaModSmallFactor) Execute(c *x509.Certificate) *LintResult {
	key := c.PublicKey.(*rsa.PublicKey)
	if util.PrimeNoSmallerThan752(key.N) {
		return &LintResult{Status: Pass}
	}
	return &LintResult{Status: Warn}

}

func init() {
	RegisterLint(&Lint{
		Name:          "w_rsa_mod_factors_smaller_than_752",
		Description:   "RSA: Modulus SHOULD also have the following characteristics: no factors smaller than 752",
		Citation:      "BRs: 6.1.6",
		Source:        CABFBaselineRequirements,
		EffectiveDate: util.CABV113Date,
		Lint:          &rsaModSmallFactor{},
	})
}
