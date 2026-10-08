// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_createIPsecKey(t *testing.T) {
	testCases := []struct {
		algo        string
		expectedKey ipsecKey
	}{
		{
			algo: "rfc4106-gcm-aes",
			expectedKey: ipsecKey{
				spi:  1,
				algo: "rfc4106(gcm(aes))",
				key:  "1234567890123456789012345678901234567890",
				size: 128,
			},
		},
		{
			algo: "cbc-aes-sha256",
			expectedKey: ipsecKey{
				spi:        1,
				algo:       "hmac(sha256)",
				key:        "12345678901234567890123456789012",
				cipherKey:  "12345678901234567890123456789012",
				cipherMode: "cbc(aes)",
			},
		},
		{
			algo: "cbc-aes-sha512",
			expectedKey: ipsecKey{
				spi:        1,
				algo:       "hmac(sha512)",
				key:        "1234567890123456789012345678901234567890123456789012345678901234",
				cipherKey:  "12345678901234567890123456789012",
				cipherMode: "cbc(aes)",
			},
		},
	}

	for _, tt := range testCases {
		actualKey, err := createIPsecKey(tt.algo)

		require.NoError(t, err)
		require.Equal(t, tt.expectedKey.spi, actualKey.spi)
		require.Equal(t, tt.expectedKey.algo, actualKey.algo)
		require.Len(t, tt.expectedKey.key, len(actualKey.key))
		require.Len(t, tt.expectedKey.cipherKey, len(actualKey.cipherKey))
		require.Equal(t, tt.expectedKey.cipherMode, actualKey.cipherMode)
		require.Equal(t, tt.expectedKey.size, actualKey.size)
	}

}
