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
The freshest CRL extension identifies how delta CRL information is obtained. The extension MUST be marked as non-critical by conforming CAs. Further discussion of CRL management is contained in Section 5.
************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/util"
)

type ExtFreshestCrlMarkedCritical struct{}

func (l *ExtFreshestCrlMarkedCritical) Initialize() error {
	return nil
}

func (l *ExtFreshestCrlMarkedCritical) CheckApplies(cert *x509.Certificate) bool {
	return util.IsExtInCert(cert, util.FreshCRLOID)
}

func (l *ExtFreshestCrlMarkedCritical) Execute(cert *x509.Certificate) *LintResult {
	var fCRL *pkix.Extension = util.GetExtFromCert(cert, util.FreshCRLOID)
	if fCRL != nil && fCRL.Critical {
		return &LintResult{Status: Error}
	} else if fCRL != nil && !fCRL.Critical {
		return &LintResult{Status: Pass}
	}
	return &LintResult{Status: NA} //shouldn't happen
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ext_freshest_crl_marked_critical",
		Description:   "Freshest CRL MUST be marked as non-critical by conforming CAs",
		Citation:      "RFC 5280: 4.2.1.15",
		Source:        RFC5280,
		EffectiveDate: util.RFC3280Date,
		Lint:          &ExtFreshestCrlMarkedCritical{},
	})
}
