// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package accesslog

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/require"
)

func TestLogRecordGobPreservesIdentityProvided(t *testing.T) {
	want := LogRecord{
		SourceEndpoint: EndpointInfo{
			Identity:                 101,
			SecurityIdentityProvided: true,
		},
		DestinationEndpoint: EndpointInfo{
			Identity:                 202,
			SecurityIdentityProvided: true,
		},
	}

	var wire bytes.Buffer
	require.NoError(t, gob.NewEncoder(&wire).Encode(want))

	var got LogRecord
	require.NoError(t, gob.NewDecoder(&wire).Decode(&got))
	require.Equal(t, want, got)
	require.True(t, got.SourceEndpoint.SecurityIdentityProvided)
	require.True(t, got.DestinationEndpoint.SecurityIdentityProvided)
}

func TestLogRecordGobDecodesRecordsWithoutIdentityProvided(t *testing.T) {
	type legacyEndpointInfo struct {
		Identity uint64
	}
	type legacyLogRecord struct {
		SourceEndpoint      legacyEndpointInfo
		DestinationEndpoint legacyEndpointInfo
	}

	want := legacyLogRecord{
		SourceEndpoint:      legacyEndpointInfo{Identity: 303},
		DestinationEndpoint: legacyEndpointInfo{Identity: 404},
	}
	var wire bytes.Buffer
	require.NoError(t, gob.NewEncoder(&wire).Encode(want))

	var got LogRecord
	require.NoError(t, gob.NewDecoder(&wire).Decode(&got))
	require.Equal(t, want.SourceEndpoint.Identity, got.SourceEndpoint.Identity)
	require.Equal(t, want.DestinationEndpoint.Identity, got.DestinationEndpoint.Identity)
	require.False(t, got.SourceEndpoint.SecurityIdentityProvided)
	require.False(t, got.DestinationEndpoint.SecurityIdentityProvided)
}

func TestEndpointInfoJSONHidesIdentityProvided(t *testing.T) {
	assertJSONHidesIdentityProvided(t, EndpointInfo{
		Identity:                 101,
		SecurityIdentityProvided: true,
	})
}

func TestLogRecordJSONHidesIdentityProvided(t *testing.T) {
	assertJSONHidesIdentityProvided(t, LogRecord{
		SourceEndpoint: EndpointInfo{
			Identity:                 101,
			SecurityIdentityProvided: true,
		},
		DestinationEndpoint: EndpointInfo{
			Identity:                 202,
			SecurityIdentityProvided: true,
		},
	})
}

func assertJSONHidesIdentityProvided(t *testing.T, value any) {
	t.Helper()

	data, err := json.Marshal(value)
	require.NoError(t, err)

	var decoded any
	require.NoError(t, json.Unmarshal(data, &decoded))
	assertNoIdentityProvenanceKey(t, decoded)
}

func assertNoIdentityProvenanceKey(t *testing.T, value any) {
	t.Helper()

	switch value := value.(type) {
	case map[string]any:
		for key, nested := range value {
			normalized := strings.Map(func(r rune) rune {
				if unicode.IsLetter(r) {
					return unicode.ToLower(r)
				}
				return -1
			}, key)
			require.NotContains(t, normalized, "identityprovided", "JSON exposed identity provenance as %q", key)
			require.NotContains(t, normalized, "identityknown", "JSON exposed derived identity provenance as %q", key)
			assertNoIdentityProvenanceKey(t, nested)
		}
	case []any:
		for _, nested := range value {
			assertNoIdentityProvenanceKey(t, nested)
		}
	}
}
