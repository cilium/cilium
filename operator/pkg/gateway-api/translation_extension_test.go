// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOrderTranslationExtensions(t *testing.T) {
	tests := []struct {
		name        string
		extensions  []TranslationExtension
		expected    []TranslationExtension
		wantErrText string
	}{
		{
			name: "orders extensions",
			extensions: []TranslationExtension{
				testTranslationExtension{name: "last", order: 20},
				testTranslationExtension{name: "first", order: 10},
			},
			expected: []TranslationExtension{
				testTranslationExtension{name: "first", order: 10},
				testTranslationExtension{name: "last", order: 20},
			},
		},
		{
			name: "rejects duplicate names",
			extensions: []TranslationExtension{
				testTranslationExtension{name: "duplicate", order: 10},
				testTranslationExtension{name: "duplicate", order: 20},
			},
			wantErrText: "registered more than once",
		},
		{
			name: "rejects duplicate orders",
			extensions: []TranslationExtension{
				testTranslationExtension{name: "first", order: 10},
				testTranslationExtension{name: "second", order: 10},
			},
			wantErrText: "use the same order 10",
		},
		{
			name: "rejects empty names",
			extensions: []TranslationExtension{
				testTranslationExtension{order: 10},
			},
			wantErrText: "name must not be empty",
		},
		{
			name:        "rejects nil extensions",
			extensions:  []TranslationExtension{nil},
			wantErrText: "must not be nil",
		},
		{
			name: "accepts no extensions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ordered, err := orderTranslationExtensions(tt.extensions)
			if tt.wantErrText != "" {
				require.ErrorContains(t, err, tt.wantErrText)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected, ordered)
		})
	}
}

type testTranslationExtension struct {
	TranslationExtension
	name  string
	order int
}

func (e testTranslationExtension) Name() string {
	return e.name
}

func (e testTranslationExtension) Order() int {
	return e.order
}
