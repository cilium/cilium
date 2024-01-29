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
				random:    "41049390e1e2b5d6543901daab6435f4042155fe",
				size:      128,
			},
		},
		{
			have: "3+ rfc4106(gcm(aes)) 41049390e1e2b5d6543901daab6435f4042155fe 128",
			expected: ipsecKey{
				spi:       3,
				spiSuffix: true,
				algo:      "rfc4106(gcm(aes))",
				random:    "41049390e1e2b5d6543901daab6435f4042155fe",
				size:      128,
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
				random:    "41049390e1e2b5d6543901daab6435f4042155fe",
				size:      128,
			},
			expected: "3 rfc4106(gcm(aes)) 41049390e1e2b5d6543901daab6435f4042155fe 128",
		},
		{
			have: ipsecKey{
				spi:       3,
				spiSuffix: true,
				algo:      "rfc4106(gcm(aes))",
				random:    "41049390e1e2b5d6543901daab6435f4042155fe",
				size:      128,
			},
			expected: "3+ rfc4106(gcm(aes)) 41049390e1e2b5d6543901daab6435f4042155fe 128",
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
				spi:       3,
				spiSuffix: false,
				algo:      "rfc4106(gcm(aes))",
				random:    "41049390e1e2b5d6543901daab6435f4042155fe",
				size:      128,
			},
			expected: ipsecKey{
				spi:       4,
				spiSuffix: false,
				algo:      "rfc4106(gcm(aes))",
				// this field will be randomly generated, `require.NotEqual` used for verification
				random: "41049390e1e2b5d6543901daab6435f4042155fe",
				size:   128,
			},
		},
		{
			have: ipsecKey{
				spi:       16,
				spiSuffix: false,
				algo:      "rfc4106(gcm(aes))",
				random:    "41049390e1e2b5d6543901daab6435f4042155fe",
				size:      128,
			},
			expected: ipsecKey{
				spi:       1,
				spiSuffix: false,
				algo:      "rfc4106(gcm(aes))",
				// this field will be randomly generated, `require.NotEqual` used for verification
				random: "41049390e1e2b5d6543901daab6435f4042155fe",
				size:   128,
			},
		},
		{
			have: ipsecKey{
				spi:       3,
				spiSuffix: true,
				algo:      "rfc4106(gcm(aes))",
				random:    "41049390e1e2b5d6543901daab6435f4042155fe",
				size:      128,
			},
			expected: ipsecKey{
				spi:       4,
				spiSuffix: true,
				algo:      "rfc4106(gcm(aes))",
				// this field will be randomly generated, `require.NotEqual` used for verification
				random: "41049390e1e2b5d6543901daab6435f4042155fe",
				size:   128,
			},
		},
		{
			have: ipsecKey{
				spi:       16,
				spiSuffix: true,
				algo:      "rfc4106(gcm(aes))",
				random:    "41049390e1e2b5d6543901daab6435f4042155fe",
				size:      128,
			},
			expected: ipsecKey{
				spi:       1,
				spiSuffix: true,
				algo:      "rfc4106(gcm(aes))",
				// this field will be randomly generated, `require.NotEqual` used for verification
				random: "41049390e1e2b5d6543901daab6435f4042155fe",
				size:   128,
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
		require.Equal(t, len(tt.expected.random), len(actual.random))
		require.NotEqual(t, tt.expected.random, actual.random)
		require.Equal(t, tt.expected.size, actual.size)
	}
}
