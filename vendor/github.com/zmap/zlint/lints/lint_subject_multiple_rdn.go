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

type SubjectRDNHasMultipleAttribute struct{}

func (l *SubjectRDNHasMultipleAttribute) Initialize() error {
	return nil
}

func (l *SubjectRDNHasMultipleAttribute) CheckApplies(c *x509.Certificate) bool {
	return true
}

func (l *SubjectRDNHasMultipleAttribute) Execute(c *x509.Certificate) *LintResult {
	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(c.RawSubject, &subject); err != nil {
		return &LintResult{Status: Fatal}
	}
	for _, rdn := range subject {
		if len(rdn) > 1 {
			return &LintResult{Status: Notice}
		}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "n_multiple_subject_rdn",
		Description:   "Certificates typically do not have have multiple attributes in a single RDN (subject). This may be an error.",
		Citation:      "AWSLabs certlint",
		Source:        AWSLabs,
		EffectiveDate: util.ZeroDate,
		Lint:          &SubjectRDNHasMultipleAttribute{},
	})
}
