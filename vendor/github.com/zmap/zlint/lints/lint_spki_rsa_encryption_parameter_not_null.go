package lints

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

/*******************************************************************************************************
"RFC5280: RFC 4055, Section 1.2"
RSA: Encoded algorithm identifier MUST have NULL parameters.
*******************************************************************************************************/

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type rsaSPKIEncryptionParamNotNULL struct{}

func (l *rsaSPKIEncryptionParamNotNULL) Initialize() error {
	return nil
}

func (l *rsaSPKIEncryptionParamNotNULL) CheckApplies(c *x509.Certificate) bool {
	// explicitly check for util.OidRSAEncryption, as RSA-PSS or RSA-OAEP certificates might be classified with c.PublicKeyAlgorithm = RSA
	return c.PublicKeyAlgorithmOID.Equal(util.OidRSAEncryption)
}

func (l *rsaSPKIEncryptionParamNotNULL) Execute(c *x509.Certificate) *LintResult {
	input := cryptobyte.String(c.RawSubjectPublicKeyInfo)

	var publicKeyInfo cryptobyte.String
	if !input.ReadASN1(&publicKeyInfo, cryptobyte_asn1.SEQUENCE) {
		return &LintResult{Status: Fatal, Details: "error reading pkixPublicKey"}
	}

	var algorithm cryptobyte.String
	var tag cryptobyte_asn1.Tag
	// use ReadAnyElement to preserve tag and length octets
	if !publicKeyInfo.ReadAnyASN1Element(&algorithm, &tag) {
		return &LintResult{Status: Fatal, Details: "error reading pkixPublicKey"}
	}

	if err := util.CheckAlgorithmIDParamNotNULL(algorithm, util.OidRSAEncryption); err != nil {
		return &LintResult{Status: Error, Details: fmt.Sprintf("certificate pkixPublicKey %s", err.Error())}
	}

	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_spki_rsa_encryption_parameter_not_null",
		Description:   "RSA: Encoded public key algorithm identifier MUST have NULL parameters",
		Citation:      "RFC 4055, Section 1.2",
		Source:        RFC5280, // RFC4055 is referenced in RFC5280, Section 1
		EffectiveDate: util.RFC5280Date,
		Lint:          &rsaSPKIEncryptionParamNotNULL{},
	})
}
