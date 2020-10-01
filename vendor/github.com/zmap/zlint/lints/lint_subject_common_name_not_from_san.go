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
BRs: 7.1.4.2.2
If present, this field MUST contain a single IP address
or Fully‐Qualified Domain Name that is one of the values
contained in the Certificate’s subjectAltName extension (see Section 7.1.4.2.1).
************************************************/

import (
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type subjectCommonNameNotFromSAN struct{}

func (l *subjectCommonNameNotFromSAN) Initialize() error {
	return nil
}

func (l *subjectCommonNameNotFromSAN) CheckApplies(c *x509.Certificate) bool {
	return c.Subject.CommonName != "" && !util.IsCACert(c)
}

func (l *subjectCommonNameNotFromSAN) Execute(c *x509.Certificate) *LintResult {
	cn := c.Subject.CommonName

	for _, dn := range c.DNSNames {
		if strings.EqualFold(cn, dn) {
			return &LintResult{Status: Pass}
		}
	}

	for _, ip := range c.IPAddresses {
		if cn == ip.String() {
			return &LintResult{Status: Pass}
		}
	}

	return &LintResult{Status: Error}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_subject_common_name_not_from_san",
		Description:   "The common name field in subscriber certificates must include only names from the SAN extension",
		Citation:      "BRs: 7.1.4.2.2",
		Source:        CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          &subjectCommonNameNotFromSAN{},
	})
}
