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
	"encoding/asn1"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/util"
)

type IssuerRDNHasMultipleAttribute struct{}

func (l *IssuerRDNHasMultipleAttribute) Initialize() error {
	return nil
}

func (l *IssuerRDNHasMultipleAttribute) CheckApplies(c *x509.Certificate) bool {
	return true
}

func (l *IssuerRDNHasMultipleAttribute) Execute(c *x509.Certificate) *LintResult {
	var issuer pkix.RDNSequence
	_, err := asn1.Unmarshal(c.RawIssuer, &issuer)
	if err != nil {
		return &LintResult{Status: Fatal}
	}
	for _, rdn := range issuer {
		if len(rdn) > 1 {
			return &LintResult{Status: Warn}
		}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "w_multiple_issuer_rdn",
		Description:   "Certificates should not have multiple attributes in a single RDN (issuer)",
		Citation:      "awslabs certlint",
		Source:        AWSLabs,
		EffectiveDate: util.ZeroDate,
		Lint:          &IssuerRDNHasMultipleAttribute{},
	})
}
