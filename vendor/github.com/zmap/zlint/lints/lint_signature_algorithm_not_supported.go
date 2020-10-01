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

type signatureAlgorithmNotSupported struct{}

func (l *signatureAlgorithmNotSupported) Initialize() error {
	return nil
}

func (l *signatureAlgorithmNotSupported) CheckApplies(c *x509.Certificate) bool {
	return true
}

func (l *signatureAlgorithmNotSupported) Execute(c *x509.Certificate) *LintResult {

	if c.SignatureAlgorithm == x509.SHA1WithRSA || c.SignatureAlgorithm == x509.SHA256WithRSA || c.SignatureAlgorithm == x509.SHA384WithRSA || c.SignatureAlgorithm == x509.SHA512WithRSA || c.SignatureAlgorithm == x509.DSAWithSHA1 || c.SignatureAlgorithm == x509.DSAWithSHA256 || c.SignatureAlgorithm == x509.ECDSAWithSHA1 || c.SignatureAlgorithm == x509.ECDSAWithSHA256 || c.SignatureAlgorithm == x509.ECDSAWithSHA384 || c.SignatureAlgorithm == x509.ECDSAWithSHA512 {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_signature_algorithm_not_supported",
		Description:   "Certificates MUST meet the following requirements for algorithm Source: SHA-1*, SHA-256, SHA-384, SHA-512",
		Citation:      "BRs: 6.1.5",
		Source:        CABFBaselineRequirements,
		EffectiveDate: util.ZeroDate,
		Lint:          &signatureAlgorithmNotSupported{},
	})
}
