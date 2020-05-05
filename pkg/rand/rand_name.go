// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
