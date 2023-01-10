// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rand

import (
	"time"
)

// Stolen from:
// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-golang

var (
	randGen = NewSafeRand(time.Now().UnixNano())

	letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
)

// RandomStringWithPrefix returns a random string of length n + len(prefix) with
// the given prefix, containing upper- and lowercase runes.
func RandomStringWithPrefix(prefix string, n int) string {
	return prefix + RandomStringWithLen(n)
}

func randomStringFromSliceWithLen(runes []rune, n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[randGen.Intn(len(runes))]
	}
	return string(b)
}

// RandomStringWithLen returns a random string of specified length containing
// upper- and lowercase runes.
func RandomStringWithLen(n int) string {
	return randomStringFromSliceWithLen(letterRunes, n)
}

// RandomLowercaseStringWithLen returns a random string of specified length
// containing lowercase runes.
func RandomLowercaseStringWithLen(n int) string {
	return randomStringFromSliceWithLen(letterRunes[:26], n)
}

// RandomString returns a random string with a predefined length of 12.
func RandomString() string {
	return RandomStringWithLen(12)
}
