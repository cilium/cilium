/*
 * ZLint Copyright 2017 Regents of the University of Michigan
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

package util

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"reflect"
)

func etsiOidToDescString(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(IdEtsiQcsQcCompliance):
		{
			return "IdEtsiQcsQcCompliance"
		}
	case oid.Equal(IdEtsiQcsQcLimitValue):
		{
			return "IdEtsiQcsQcLimitValue"
		}
	case oid.Equal(IdEtsiQcsQcRetentionPeriod):
		{
			return "IdEtsiQcsQcRetentionPeriod"
		}
	case oid.Equal(IdEtsiQcsQcSSCD):
		{
			return "IdEtsiQcsQcSSCSD"
		}
	case oid.Equal(IdEtsiQcsQcEuPDS):
		{
			return "IdEtsiQcsQcEuPDS"
		}
	case oid.Equal(IdEtsiQcsQcType):
		{
			return "IdEtsiQcsQcType"
		}
	default:
		{
			panic("unresolved ETSI QC Statement OID")
		}
	}
}

type anyContent struct {
	Raw asn1.RawContent
}

type qcStatementWithInfoField struct {
	Oid asn1.ObjectIdentifier
	Any asn1.RawValue
}
type qcStatementWithoutInfoField struct {
	Oid asn1.ObjectIdentifier
}

type etsiBase struct {
	errorInfo string
	isPresent bool
}

func (this etsiBase) GetErrorInfo() string {
	return this.errorInfo
}

func (this etsiBase) IsPresent() bool {
	return this.isPresent
}

type EtsiQcStmtIf interface {
	GetErrorInfo() string
	IsPresent() bool
}

type Etsi421QualEuCert struct {
	etsiBase
}

type Etsi423QcType struct {
	etsiBase
	TypeOids []asn1.ObjectIdentifier
}

type EtsiQcSscd struct {
	etsiBase
}

type EtsiMonetaryValueAlph struct {
	iso4217CurrencyCodeAlph string `asn1:"printable"`
	amount                  int
	exponent                int
}
type EtsiMonetaryValueNum struct {
	iso4217CurrencyCodeNum int
	amount                 int
	exponent               int
}

type EtsiQcLimitValue struct {
	etsiBase
	Amount       int
	Exponent     int
	IsNum        bool
	CurrencyAlph string
	CurrencyNum  int
}

type EtsiQcRetentionPeriod struct {
	etsiBase
	Period int
}
type PdsLocation struct {
	Url      string `asn1:"ia5"`
	Language string `asn1:"printable"`
}
type EtsiQcPds struct {
	etsiBase
	PdsLocations []PdsLocation
}

func AppendToStringSemicolonDelim(this *string, s string) {
	if len(*this) > 0 && len(s) > 0 {
		(*this) += "; "
	}
	(*this) += s
}

func checkAsn1Reencoding(i interface{}, originalEncoding []byte, appendIfComparisonFails string) string {
	result := ""
	reencoded, marshErr := asn1.Marshal(i)
	if marshErr != nil {
		AppendToStringSemicolonDelim(&result, fmt.Sprintf("error reencoding ASN1 value of statementInfo field: %s",
			marshErr))
	}
	if !bytes.Equal(reencoded, originalEncoding) {
		AppendToStringSemicolonDelim(&result, appendIfComparisonFails)
	}
	return result
}

func IsAnyEtsiQcStatementPresent(extVal []byte) bool {
	oidList := make([]*asn1.ObjectIdentifier, 6)
	oidList[0] = &IdEtsiQcsQcCompliance
	oidList[1] = &IdEtsiQcsQcLimitValue
	oidList[2] = &IdEtsiQcsQcRetentionPeriod
	oidList[3] = &IdEtsiQcsQcSSCD
	oidList[4] = &IdEtsiQcsQcEuPDS
	oidList[5] = &IdEtsiQcsQcType
	for _, oid := range oidList {
		r := ParseQcStatem(extVal, *oid)
		if r.IsPresent() {
			return true
		}
	}
	return false
}

func ParseQcStatem(extVal []byte, sought asn1.ObjectIdentifier) EtsiQcStmtIf {
	sl := make([]anyContent, 0)
	rest, err := asn1.Unmarshal(extVal, &sl)
	if err != nil {
		return etsiBase{errorInfo: "error parsing outer SEQ", isPresent: true}
	}
	if len(rest) != 0 {
		return etsiBase{errorInfo: "rest len of outer seq != 0", isPresent: true}
	}

	for _, raw := range sl {
		parseErrorString := "format error in at least one QC statement within the QC statements extension." +
			" this message may appear multiple times for the same error cause."
		var statem qcStatementWithInfoField
		rest, err = asn1.Unmarshal(raw.Raw, &statem)
		if err != nil {
			var statemWithoutInfo qcStatementWithoutInfoField

			rest, err = asn1.Unmarshal(raw.Raw, &statemWithoutInfo)
			if err != nil || len(rest) != 0 {
				return etsiBase{errorInfo: parseErrorString, isPresent: false}
			}
			copy(statem.Oid, statemWithoutInfo.Oid)
			if len(statem.Any.FullBytes) != 0 {
				return etsiBase{errorInfo: "internal error, default optional content len is not zero"}
			}
		} else if 0 != len(rest) {
			return etsiBase{errorInfo: parseErrorString, isPresent: false}
		}

		if !statem.Oid.Equal(sought) {
			continue
		}
		if statem.Oid.Equal(IdEtsiQcsQcCompliance) {
			etsiObj := Etsi421QualEuCert{etsiBase: etsiBase{isPresent: true}}
			statemWithoutInfo := qcStatementWithoutInfoField{Oid: statem.Oid}
			AppendToStringSemicolonDelim(&etsiObj.errorInfo, checkAsn1Reencoding(reflect.ValueOf(statemWithoutInfo).Interface(), raw.Raw,
				"invalid format of ETSI Complicance statement"))
			return etsiObj
		} else if statem.Oid.Equal(IdEtsiQcsQcLimitValue) {
			etsiObj := EtsiQcLimitValue{etsiBase: etsiBase{isPresent: true}}
			numErr := false
			alphErr := false
			var numeric EtsiMonetaryValueNum
			var alphabetic EtsiMonetaryValueAlph
			restNum, errNum := asn1.Unmarshal(statem.Any.FullBytes, &numeric)
			if len(restNum) != 0 || errNum != nil {
				numErr = true
			} else {
				etsiObj.IsNum = true
				etsiObj.Amount = numeric.amount
				etsiObj.Exponent = numeric.exponent
				etsiObj.CurrencyNum = numeric.iso4217CurrencyCodeNum

			}
			if numErr {
				restAlph, errAlph := asn1.Unmarshal(statem.Any.FullBytes, &alphabetic)
				if len(restAlph) != 0 || errAlph != nil {
					alphErr = true
				} else {
					etsiObj.IsNum = false
					etsiObj.Amount = alphabetic.amount
					etsiObj.Exponent = alphabetic.exponent
					etsiObj.CurrencyAlph = alphabetic.iso4217CurrencyCodeAlph
					AppendToStringSemicolonDelim(&etsiObj.errorInfo,
						checkAsn1Reencoding(reflect.ValueOf(alphabetic).Interface(),
							statem.Any.FullBytes, "error with ASN.1 encoding, possibly a wrong ASN.1 string type was used"))
				}
			}
			if numErr && alphErr {
				etsiObj.errorInfo = "error parsing the ETSI Qc Statement statementInfo field"
			}
			return etsiObj

		} else if statem.Oid.Equal(IdEtsiQcsQcRetentionPeriod) {
			etsiObj := EtsiQcRetentionPeriod{etsiBase: etsiBase{isPresent: true}}
			rest, err := asn1.Unmarshal(statem.Any.FullBytes, &etsiObj.Period)

			if len(rest) != 0 || err != nil {
				etsiObj.errorInfo = "error parsing the statementInfo field"
			}
			return etsiObj
		} else if statem.Oid.Equal(IdEtsiQcsQcSSCD) {
			etsiObj := EtsiQcSscd{etsiBase: etsiBase{isPresent: true}}
			statemWithoutInfo := qcStatementWithoutInfoField{Oid: statem.Oid}
			AppendToStringSemicolonDelim(&etsiObj.errorInfo, checkAsn1Reencoding(reflect.ValueOf(statemWithoutInfo).Interface(), raw.Raw,
				"invalid format of ETSI SCSD statement"))
			return etsiObj
		} else if statem.Oid.Equal(IdEtsiQcsQcEuPDS) {
			etsiObj := EtsiQcPds{etsiBase: etsiBase{isPresent: true}}
			rest, err := asn1.Unmarshal(statem.Any.FullBytes, &etsiObj.PdsLocations)
			if len(rest) != 0 || err != nil {
				etsiObj.errorInfo = "error parsing the statementInfo field"
			} else {
				AppendToStringSemicolonDelim(&etsiObj.errorInfo,
					checkAsn1Reencoding(reflect.ValueOf(etsiObj.PdsLocations).Interface(), statem.Any.FullBytes,
						"error with ASN.1 encoding, possibly a wrong ASN.1 string type was used"))
			}
			return etsiObj
		} else if statem.Oid.Equal(IdEtsiQcsQcType) {
			var qcType Etsi423QcType
			qcType.isPresent = true
			rest, err := asn1.Unmarshal(statem.Any.FullBytes, &qcType.TypeOids)
			if len(rest) != 0 || err != nil {
				return etsiBase{errorInfo: "error parsing IdEtsiQcsQcType extension statementInfo field", isPresent: true}
			}
			return qcType
		} else {
			return etsiBase{errorInfo: "", isPresent: true}
		}

	}

	return etsiBase{errorInfo: "", isPresent: false}

}
