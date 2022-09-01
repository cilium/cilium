// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package ingress

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getMatchingPrefixRegex(t *testing.T) {
	t.Run("simple slash path", func(t *testing.T) {
		rx, err := regexp.Compile(getMatchingPrefixRegex("/"))
		assert.NoError(t, err)

		assert.True(t, rx.MatchString("/"))
		assert.True(t, rx.MatchString("/foo"))
		assert.True(t, rx.MatchString("/foo/bar"))
	})

	t.Run("simple /foo path", func(t *testing.T) {
		rx, err := regexp.Compile(getMatchingPrefixRegex("/foo"))
		assert.NoError(t, err)

		assert.False(t, rx.MatchString("/"))
		assert.False(t, rx.MatchString("/foobar"))

		assert.True(t, rx.MatchString("/foo"))
		assert.True(t, rx.MatchString("/foo/"))
		assert.True(t, rx.MatchString("/foo/bar"))
	})

	t.Run("path with trailing slash /foo/ path", func(t *testing.T) {
		rx, err := regexp.Compile(getMatchingPrefixRegex("/foo/"))
		assert.NoError(t, err)

		assert.False(t, rx.MatchString("/"))
		assert.False(t, rx.MatchString("/foobar"))

		assert.True(t, rx.MatchString("/foo"))
		assert.True(t, rx.MatchString("/foo/"))
		assert.True(t, rx.MatchString("/foo/bar"))
	})
}

func Test_getMatchingHeaderRegex(t *testing.T) {
	t.Run("starting with *.", func(t *testing.T) {
		result := getMatchingHeaderRegex("*.foo.com")
		rx, err := regexp.Compile(result)
		assert.NoError(t, err)

		// Match entire host
		assert.True(t, rx.MatchString("bar.foo.com"))

		// Not match
		assert.False(t, rx.MatchString("foo.com"))
		assert.False(t, rx.MatchString("baz.bar.foo.com"))
		assert.False(t, rx.MatchString("some.random.host.com"))
	})

	t.Run("not starting with *.", func(t *testing.T) {
		result := getMatchingHeaderRegex("foo.com")
		rx, err := regexp.Compile(result)
		assert.NoError(t, err)

		// Match entire host
		assert.True(t, rx.MatchString("foo.com"))

		// Not match
		assert.False(t, rx.MatchString("bar.foo.com"))
		assert.False(t, rx.MatchString("abc.bar.foo.com"))
		assert.False(t, rx.MatchString("some.random.host.com"))
	})
}
