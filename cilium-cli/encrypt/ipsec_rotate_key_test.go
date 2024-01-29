// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ipsecKeyFromString(t *testing.T) {
	testCases := []struct {
		have     string
		expected ipsecKey
	}{
		{
			have: "3 rfc4106(gcm(aes)) 41049390e1e2b5d6543901daab6435f4042155fe 128",
			expected: ipsecKey{
				spi:       3,
				spiSuffix: false,
				algo:      "rfc4106(gcm(aes))",
				key:       "41049390e1e2b5d6543901daab6435f4042155fe",
				size:      128,
			},
		},
		{
			have: "3+ rfc4106(gcm(aes)) 41049390e1e2b5d6543901daab6435f4042155fe 128",
			expected: ipsecKey{
				spi:       3,
				spiSuffix: true,
				algo:      "rfc4106(gcm(aes))",
				key:       "41049390e1e2b5d6543901daab6435f4042155fe",
				size:      128,
			},
		},
		{
			have: "3 hmac(sha256) e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b cbc(aes) 0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			expected: ipsecKey{
				spi:        3,
				spiSuffix:  false,
				algo:       "hmac(sha256)",
				key:        "e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b",
				size:       0,
				cipherMode: "cbc(aes)",
				cipherKey:  "0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			},
		},
		{
			have: "3+ hmac(sha256) e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b cbc(aes) 0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			expected: ipsecKey{
				spi:        3,
				spiSuffix:  true,
				algo:       "hmac(sha256)",
				key:        "e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b",
				size:       0,
				cipherMode: "cbc(aes)",
				cipherKey:  "0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			},
		},
	}

	for _, tt := range testCases {
		// function to test
		actual, err := ipsecKeyFromString(tt.have)

		require.NoError(t, err)
		require.Equal(t, tt.expected, actual)
	}
}

func Test_ipsecKey_String(t *testing.T) {
	testCases := []struct {
		have     ipsecKey
		expected string
	}{
		{
			have: ipsecKey{
				spi:       3,
				spiSuffix: false,
				algo:      "rfc4106(gcm(aes))",
				key:       "41049390e1e2b5d6543901daab6435f4042155fe",
				size:      128,
			},
			expected: "3 rfc4106(gcm(aes)) 41049390e1e2b5d6543901daab6435f4042155fe 128",
		},
		{
			have: ipsecKey{
				spi:       3,
				spiSuffix: true,
				algo:      "rfc4106(gcm(aes))",
				key:       "41049390e1e2b5d6543901daab6435f4042155fe",
				size:      128,
			},
			expected: "3+ rfc4106(gcm(aes)) 41049390e1e2b5d6543901daab6435f4042155fe 128",
		},
		{
			have: ipsecKey{
				spi:        3,
				spiSuffix:  false,
				algo:       "hmac(sha256)",
				key:        "e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b",
				size:       0,
				cipherMode: "cbc(aes)",
				cipherKey:  "0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			},
			expected: "3 hmac(sha256) e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b cbc(aes) 0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
		},
		{
			have: ipsecKey{
				spi:        3,
				spiSuffix:  true,
				algo:       "hmac(sha256)",
				key:        "e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b",
				size:       0,
				cipherMode: "cbc(aes)",
				cipherKey:  "0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			},
			expected: "3+ hmac(sha256) e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b cbc(aes) 0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
		},
	}

	for _, tt := range testCases {
		// function to test
		actual := tt.have.String()

		require.Equal(t, tt.expected, actual)
	}

}

func Test_ipsecKey_rotate(t *testing.T) {
	testCases := []struct {
		have     ipsecKey
		expected ipsecKey
	}{
		{
			have: ipsecKey{
				spi:        3,
				spiSuffix:  false,
				algo:       "rfc4106(gcm(aes))",
				key:        "41049390e1e2b5d6543901daab6435f4042155fe",
				size:       128,
				cipherMode: "",
				cipherKey:  "",
			},
			expected: ipsecKey{
				spi:       4,
				spiSuffix: false,
				algo:      "rfc4106(gcm(aes))",
				// this field will be randomly generated, `require.NotEqual` used for verification
				key:        "41049390e1e2b5d6543901daab6435f4042155fe",
				size:       128,
				cipherMode: "",
				cipherKey:  "",
			},
		},
		{
			have: ipsecKey{
				spi:        16,
				spiSuffix:  false,
				algo:       "rfc4106(gcm(aes))",
				key:        "41049390e1e2b5d6543901daab6435f4042155fe",
				size:       128,
				cipherMode: "",
				cipherKey:  "",
			},
			expected: ipsecKey{
				spi:       1,
				spiSuffix: false,
				algo:      "rfc4106(gcm(aes))",
				// this field will be randomly generated, `require.NotEqual` used for verification
				key:        "41049390e1e2b5d6543901daab6435f4042155fe",
				size:       128,
				cipherMode: "",
				cipherKey:  "",
			},
		},
		{
			have: ipsecKey{
				spi:        3,
				spiSuffix:  true,
				algo:       "rfc4106(gcm(aes))",
				key:        "41049390e1e2b5d6543901daab6435f4042155fe",
				size:       128,
				cipherMode: "",
				cipherKey:  "",
			},
			expected: ipsecKey{
				spi:       4,
				spiSuffix: true,
				algo:      "rfc4106(gcm(aes))",
				// this field will be randomly generated, `require.NotEqual` used for verification
				key:        "41049390e1e2b5d6543901daab6435f4042155fe",
				size:       128,
				cipherMode: "",
				cipherKey:  "",
			},
		},
		{
			have: ipsecKey{
				spi:        16,
				spiSuffix:  true,
				algo:       "rfc4106(gcm(aes))",
				key:        "41049390e1e2b5d6543901daab6435f4042155fe",
				size:       128,
				cipherMode: "",
				cipherKey:  "",
			},
			expected: ipsecKey{
				spi:       1,
				spiSuffix: true,
				algo:      "rfc4106(gcm(aes))",
				// this field will be randomly generated, `require.NotEqual` used for verification
				key:        "41049390e1e2b5d6543901daab6435f4042155fe",
				size:       128,
				cipherMode: "",
				cipherKey:  "",
			},
		},
		{
			have: ipsecKey{
				spi:        3,
				spiSuffix:  false,
				algo:       "hmac(sha256)",
				key:        "e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b",
				size:       0,
				cipherMode: "cbc(aes)",
				cipherKey:  "0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			},
			expected: ipsecKey{
				spi:       4,
				spiSuffix: false,
				algo:      "hmac(sha256)",
				// this field will be randomly generated, `require.NotEqual` used for verification
				key:        "e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b",
				size:       0,
				cipherMode: "cbc(aes)",
				// this field will be randomly generated, `require.NotEqual` used for verification
				cipherKey: "0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			},
		},
		{
			have: ipsecKey{
				spi:        16,
				spiSuffix:  false,
				algo:       "hmac(sha256)",
				key:        "e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b",
				size:       0,
				cipherMode: "cbc(aes)",
				cipherKey:  "0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			},
			expected: ipsecKey{
				spi:       1,
				spiSuffix: false,
				algo:      "hmac(sha256)",
				// this field will be randomly generated, `require.NotEqual` used for verification
				key:        "e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b",
				size:       0,
				cipherMode: "cbc(aes)",
				// this field will be randomly generated, `require.NotEqual` used for verification
				cipherKey: "0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			},
		},
		{
			have: ipsecKey{
				spi:        3,
				spiSuffix:  true,
				algo:       "hmac(sha256)",
				key:        "e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b",
				size:       0,
				cipherMode: "cbc(aes)",
				cipherKey:  "0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			},
			expected: ipsecKey{
				spi:       4,
				spiSuffix: true,
				algo:      "hmac(sha256)",
				// this field will be randomly generated, `require.NotEqual` used for verification
				key:        "e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b",
				size:       0,
				cipherMode: "cbc(aes)",
				// this field will be randomly generated, `require.NotEqual` used for verification
				cipherKey: "0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			},
		},
		{
			have: ipsecKey{
				spi:        16,
				spiSuffix:  true,
				algo:       "hmac(sha256)",
				key:        "e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b",
				size:       0,
				cipherMode: "cbc(aes)",
				cipherKey:  "0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			},
			expected: ipsecKey{
				spi:       1,
				spiSuffix: true,
				algo:      "hmac(sha256)",
				// this field will be randomly generated, `require.NotEqual` used for verification
				key:        "e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b",
				size:       0,
				cipherMode: "cbc(aes)",
				// this field will be randomly generated, `require.NotEqual` used for verification
				cipherKey: "0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			},
		},
	}

	for _, tt := range testCases {
		// function to test
		actual, err := tt.have.rotate()

		require.NoError(t, err)
		require.Equal(t, tt.expected.spi, actual.spi)
		require.Equal(t, tt.expected.spiSuffix, actual.spiSuffix)
		require.Equal(t, tt.expected.algo, actual.algo)
		require.Equal(t, len(tt.expected.key), len(actual.key))
		require.Equal(t, len(tt.expected.cipherKey), len(actual.cipherKey))
		require.Equal(t, tt.expected.size, actual.size)
		require.Equal(t, tt.expected.cipherMode, actual.cipherMode)
		if tt.expected.cipherMode == "" {
			require.NotEqual(t, tt.expected.key, actual.key)
			require.Equal(t, tt.expected.cipherKey, actual.cipherKey)
		} else {
			require.NotEqual(t, tt.expected.key, actual.key)
			require.NotEqual(t, tt.expected.cipherKey, actual.cipherKey)
		}
	}
}
