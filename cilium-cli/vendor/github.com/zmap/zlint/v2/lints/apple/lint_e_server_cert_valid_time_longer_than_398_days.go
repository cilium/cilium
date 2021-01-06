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

package apple

import (
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v2/lint"
	"github.com/zmap/zlint/v2/util"
)

type serverCertValidityTooLong struct{}

func (l *serverCertValidityTooLong) Initialize() error {
	return nil
}

func (l *serverCertValidityTooLong) CheckApplies(c *x509.Certificate) bool {
	return util.IsServerAuthCert(c) && !c.IsCA
}

func (l *serverCertValidityTooLong) Execute(c *x509.Certificate) *lint.LintResult {
	// "398 days is measured with a day being equal to 86,400 seconds. Any time
	// greater than this indicates an additional day of validity."
	dayLength := 86400 * time.Second
	// "TLS server certificates issued on or after September 1, 2020 00:00 GMT/UTC
	// must not have a validity period greater than 398 days."
	maxValidity := 398 * dayLength
	// "We recommend that certificates be issued with a maximum validity of 397 days."
	warnValidity := 397 * dayLength

	// RFC 5280, section 4.1.2.5: "The validity period for a certificate is the period
	// of time from notBefore through notAfter, inclusive."
	certValidity := c.NotAfter.Add(1 * time.Second).Sub(c.NotBefore)

	if certValidity > maxValidity {
		return &lint.LintResult{Status: lint.Error}
	} else if certValidity > warnValidity {
		return &lint.LintResult{
			// RFC 2119 has SHOULD and RECOMMENDED as equal. Since Apple recommends
			// 397 days we treat this as a lint.Warn result as a violation of
			// a SHOULD.
			Status: lint.Warn,
			Details: "Apple recommends that certificates be issued with a maximum " +
				"validity of 397 days.",
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name: "e_tls_server_cert_valid_time_longer_than_398_days",
		Description: "TLS server certificates issued on or after September 1, 2020 " +
			"00:00 GMT/UTC must not have a validity period greater than 398 days",
		Citation: "https://support.apple.com/en-us/HT211025",
		// TODO(@cpu): The Source should be `lint.ApplePolicy` or something similar.
		// The "CT" bit is too specific. Unfortunately since the constant is
		// exported by the `util` package we can't change it without bumping the
		// major version. See https://github.com/zmap/zlint/issues/418
		Source:        lint.AppleCTPolicy,
		EffectiveDate: util.AppleReducedLifetimeDate,
		Lint:          &serverCertValidityTooLong{},
	})
}
