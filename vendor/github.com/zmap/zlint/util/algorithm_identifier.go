package util

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// RSAAlgorithmIDToDER contains DER representations of pkix.AlgorithmIdentifier for different RSA OIDs with Parameters as asn1.NULL
var RSAAlgorithmIDToDER = map[string][]byte{
	// rsaEncryption
	"1.2.840.113549.1.1.1": {0x30, 0x0d, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1, 0x5, 0x0},
	// md2WithRSAEncryption
	"1.2.840.113549.1.1.2": {0x30, 0x0d, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x2, 0x5, 0x0},
	// md5WithRSAEncryption
	"1.2.840.113549.1.1.4": {0x30, 0x0d, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x4, 0x5, 0x0},
	// sha-1WithRSAEncryption
	"1.2.840.113549.1.1.5": {0x30, 0x0d, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x5, 0x5, 0x0},
	// sha224WithRSAEncryption
	"1.2.840.113549.1.1.14": {0x30, 0x0d, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0xe, 0x5, 0x0},
	// sha256WithRSAEncryption
	"1.2.840.113549.1.1.11": {0x30, 0x0d, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0xb, 0x5, 0x0},
	// sha384WithRSAEncryption
	"1.2.840.113549.1.1.12": {0x30, 0x0d, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0xc, 0x5, 0x0},
	// sha512WithRSAEncryption
	"1.2.840.113549.1.1.13": {0x30, 0x0d, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0xd, 0x5, 0x0},
}

// CheckAlgorithmIDParamNotNULL parses an AlgorithmIdentifier with algorithm OID rsaEncryption to check the Param field is asn1.NULL
// Expects DER-encoded AlgorithmIdentifier including tag and length
func CheckAlgorithmIDParamNotNULL(algorithmIdentifier []byte, requiredAlgoID asn1.ObjectIdentifier) error {
	expectedAlgoIDBytes, ok := RSAAlgorithmIDToDER[requiredAlgoID.String()]
	if !ok {
		return errors.New("error algorithmID to check is not RSA")
	}

	algorithmSequence := cryptobyte.String(algorithmIdentifier)

	// byte comparison of algorithm sequence and checking no trailing data is present
	var algorithmBytes []byte
	if algorithmSequence.ReadBytes(&algorithmBytes, len(expectedAlgoIDBytes)) {
		if bytes.Compare(algorithmBytes, expectedAlgoIDBytes) == 0 && algorithmSequence.Empty() {
			return nil
		}
	}

	// re-parse to get an error message detailing what did not match in the byte comparison
	algorithmSequence = cryptobyte.String(algorithmIdentifier)
	var algorithm cryptobyte.String
	if !algorithmSequence.ReadASN1(&algorithm, cryptobyte_asn1.SEQUENCE) {
		return errors.New("error reading algorithm")
	}

	encryptionOID := asn1.ObjectIdentifier{}
	if !algorithm.ReadASN1ObjectIdentifier(&encryptionOID) {
		return errors.New("error reading algorithm OID")
	}

	if !encryptionOID.Equal(requiredAlgoID) {
		return fmt.Errorf("algorithm OID is not equal to %s", requiredAlgoID.String())
	}

	if algorithm.Empty() {
		return errors.New("RSA algorithm identifier missing required NULL parameter")
	}

	var nullValue cryptobyte.String
	if !algorithm.ReadASN1(&nullValue, cryptobyte_asn1.NULL) {
		return errors.New("RSA algorithm identifier with non-NULL parameter")
	}

	if len(nullValue) != 0 {
		return errors.New("RSA algorithm identifier with NULL parameter containing data")
	}

	// ensure algorithm is empty and no trailing data is present
	if !algorithm.Empty() {
		return errors.New("RSA algorithm identifier with trailing data")
	}

	return errors.New("RSA algorithm appears correct, but didn't match byte-wise comparison")
}
