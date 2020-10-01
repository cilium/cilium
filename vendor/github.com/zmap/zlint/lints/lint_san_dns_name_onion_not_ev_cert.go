/*
 * ZLint Copyright 2019 Regents of the University of Michigan
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

package lints

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

const (
	// onionTLD is a const for the TLD for Tor Hidden Services.
	onionTLD = ".onion"
)

type onionNotEV struct{}

// Initialize for an onionNotEV linter is a NOP.
func (l *onionNotEV) Initialize() error {
	return nil
}

// CheckApplies returns true if the certificate is a subscriber certificate that
// contains a subject name ending in `.onion`.
func (l *onionNotEV) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.CertificateSubjInTLD(c, onionTLD)
}

// Execute returns an Error LintResult if the certificate is not an EV
// certificate. CheckApplies has already verified the certificate contains one
// or more `.onion` subjects and so it must be an EV certificate.
func (l *onionNotEV) Execute(c *x509.Certificate) *LintResult {
	/*
	 * Effective May 1, 2015, each CA SHALL revoke all unexpired Certificates with an
	 * Internal Name using onion as the right-most label in an entry in the
	 * subjectAltName Extension or commonName field unless such Certificate was
	 * issued in accordance with Appendix F of the EV Guidelines.
	 */
	if !util.IsEV(c.PolicyIdentifiers) {
		return &LintResult{
			Status: Error,
			Details: fmt.Sprintf(
				"certificate contains one or more %s subject domains but is not an EV certificate",
				onionTLD),
		}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_san_dns_name_onion_not_ev_cert",
		Description:   "certificates with a .onion subject name must be issued in accordance with EV Guidelines",
		Citation:      "CABF Ballot 144",
		Source:        CABFBaselineRequirements,
		EffectiveDate: util.OnionOnlyEVDate,
		Lint:          &onionNotEV{},
	})
}
