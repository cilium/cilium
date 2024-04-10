// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnnotationMap(t *testing.T) {
	var a annotationsMap
	err := a.Set(`not json`)
	assert.IsType(t, err, &json.SyntaxError{})

	err = a.Set(`{"foo*bar":{}}`)
	assert.ErrorContains(t, err, "wildcard only allowed at end of key")

	err = a.Set(`{"baz*qux*":{}}`)
	assert.ErrorContains(t, err, "wildcard only allowed at end of key")

	err = a.Set(`{"**":{}}`)
	assert.ErrorContains(t, err, "wildcard only allowed at end of key")

	var clientAnnotations = annotations{"baz": "qux"}
	var echoSameNodeAnnotations = annotations{"quux": "corge"}
	var echoWildcardAnnotations = annotations{"grault": "grault"}
	var wildcardAnnotations = annotations{"waldo": "fred"}

	err = a.Set(`{
		"client": ` + clientAnnotations.String() + `,
		"echo-same-node": ` + echoSameNodeAnnotations.String() + `,
		"echo*": ` + echoWildcardAnnotations.String() + `,
		"*": ` + wildcardAnnotations.String() + `
	}`)
	assert.NoError(t, err)
	assert.Equal(t, annotationsMap{
		"client":         clientAnnotations,
		"echo-same-node": echoSameNodeAnnotations,
		"echo*":          echoWildcardAnnotations,
		"*":              wildcardAnnotations,
	}, a)

	// Test wildcard fallback
	assert.Equal(t, a.Match("echo*"), annotations(nil)) // wildcard not allowed here
	assert.Equal(t, a.Match("*"), annotations(nil))     // wildcard not allowed here

	assert.Equal(t, a.Match("client"), clientAnnotations)
	assert.Equal(t, a.Match("echo-same-node"), echoSameNodeAnnotations)
	assert.Equal(t, a.Match("echo-other-node"), echoWildcardAnnotations)
	assert.Equal(t, a.Match("other"), wildcardAnnotations)

	err = a.Set(`{
		"echo-same-*": ` + echoSameNodeAnnotations.String() + `,
		"echo*": ` + echoWildcardAnnotations.String() + `
	}`)
	assert.NoError(t, err)
	assert.Equal(t, annotationsMap{
		"echo-same-*": echoSameNodeAnnotations,
		"echo*":       echoWildcardAnnotations,
	}, a)

	// Tests longest prefix match
	assert.Equal(t, a.Match("echo-same-node"), echoSameNodeAnnotations)
	assert.Equal(t, a.Match("echo-other-node"), echoWildcardAnnotations)
	assert.Equal(t, a.Match("echo"), echoWildcardAnnotations)
	assert.Equal(t, a.Match("other"), annotations(nil))

}
