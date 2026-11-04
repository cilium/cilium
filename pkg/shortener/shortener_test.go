// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package shortener

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/validation"
)

func TestShorten(t *testing.T) {
	limit := k8sMaxResourceNameLength

	// Shorter than limit
	shorterName := "short"

	// Equal to limit
	equalName := "l" + strings.Repeat("o", limit-3) + "ng"

	// Longer than limit
	longerName := "very-l" + strings.Repeat("o", limit) + "ng"

	shorterResult0 := shorten(shorterName, limit)
	equalResult0 := shorten(equalName, limit)
	longerResult0 := shorten(longerName, limit)

	assert.Equal(t, shorterName, shorterResult0, "Shorter name wasn't kept as is")
	assert.Equal(t, equalName, equalResult0, "Equal name wasn't kept as is")
	assert.Len(t, longerResult0, 63, "Longer name wasn't shortened")

	t.Logf("Shorter Name: %s", shorterResult0)
	t.Logf("Equal Name  : %s", equalResult0)
	t.Logf("Longer Name : %s", longerResult0)
	t.Logf("Limit       : %s", strings.Repeat("=", limit))

	shorterResult1 := shorten(shorterName, limit)
	equalResult1 := shorten(equalName, limit)
	longerResult1 := shorten(longerName, limit)

	assert.Equal(t, shorterResult0, shorterResult1, "Shorter name wasn't matched with previous result")
	assert.Equal(t, equalResult0, equalResult1, "Equal name wasn't matched with previous result")
	assert.Equal(t, longerResult0, longerResult1, "Longer name wasn't matched with previous result")
}

func TestShortenDNSSubdomainK8sDNSLabelEdgeCase(t *testing.T) {
	// The dot would fall exactly at the truncation boundary before the hash suffix.
	name := strings.Repeat("a", k8sMaxResourceNameDNSSubdomainLength-12) + ".bbb" + strings.Repeat("c", 20)
	shortened := ShortenDNSSubdomainK8sName(name)
	assert.Equal(t, strings.Repeat("a", 241)+"-4cdbbcg65m", shortened)
	assert.Empty(t, validation.IsDNS1123Subdomain(shortened))
}
