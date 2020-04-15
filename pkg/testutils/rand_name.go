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

package testutils

import (
	"math/rand"
	"time"
)

// Stolen from:
// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-golang
func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// RandomStringWithPrefix returns a random string of length n + len(prefix) with
// the given prefix, containing upper- and lowercase runes.
func RandomStringWithPrefix(prefix string, n int) string {
	return prefix + RandomStringWithLen(n)
}

// RandomStringWithLen returns a random string of specified length containing
// upper- and lowercase runes.
func RandomStringWithLen(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// RandomString returns a random string with a predefined length of 12.
func RandomString() string {
	return RandomStringWithLen(12)
}
