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
The name MUST include both a
scheme (e.g., "http" or "ftp") and a scheme-specific-part.
************************************************/

import (
	"net/url"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type extSANURIFormatInvalid struct{}

func (l *extSANURIFormatInvalid) Initialize() error {
	return nil
}

func (l *extSANURIFormatInvalid) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.SubjectAlternateNameOID)
}

func (l *extSANURIFormatInvalid) Execute(c *x509.Certificate) *LintResult {
	for _, uri := range c.URIs {
		parsed_uri, err := url.Parse(uri)

		if err != nil {
			return &LintResult{Status: Error}
		}

		//scheme
		if parsed_uri.Scheme == "" {
			return &LintResult{Status: Error}
		}

		//scheme-specific part
		if parsed_uri.Host == "" && parsed_uri.User == nil && parsed_uri.Opaque == "" && parsed_uri.Path == "" {
			return &LintResult{Status: Error}
		}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ext_san_uri_format_invalid",
		Description:   "URIs in SAN extension must have a scheme and scheme specific part",
		Citation:      "RFC5280: 4.2.1.6",
		Source:        RFC5280,
		EffectiveDate: util.RFC5280Date,
		Lint:          &extSANURIFormatInvalid{},
	})
}
