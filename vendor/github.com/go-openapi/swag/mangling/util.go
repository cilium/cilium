// Copyright 2015 go-swagger maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mangling

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Removes leading whitespaces
func trim(str string) string { return strings.TrimSpace(str) }

// upper is strings.ToUpper() combined with trim
func upper(str string) string {
	return strings.ToUpper(trim(str))
}

// lower is strings.ToLower() combined with trim
func lower(str string) string {
	return strings.ToLower(trim(str))
}

// isEqualFoldIgnoreSpace is the same as strings.EqualFold, but
// it ignores leading and trailing blank spaces in the compared
// string.
//
// base is assumed to be composed of upper-cased runes, and be already
// trimmed.
//
// This code is heavily inspired from strings.EqualFold.
func isEqualFoldIgnoreSpace(base []rune, str string) bool {
	var i, baseIndex int
	// equivalent to b := []byte(str), but without data copy
	b := hackStringBytes(str)

	for i < len(b) {
		if c := b[i]; c < utf8.RuneSelf {
			// fast path for ASCII
			if c != ' ' && c != '\t' {
				break
			}
			i++

			continue
		}

		// unicode case
		r, size := utf8.DecodeRune(b[i:])
		if !unicode.IsSpace(r) {
			break
		}
		i += size
	}

	if i >= len(b) {
		return len(base) == 0
	}

	for _, baseRune := range base {
		if i >= len(b) {
			break
		}

		if c := b[i]; c < utf8.RuneSelf {
			// single byte rune case (ASCII)
			if baseRune >= utf8.RuneSelf {
				return false
			}

			baseChar := byte(baseRune)
			if c != baseChar && ((c < 'a') || (c > 'z') || (c-'a'+'A' != baseChar)) {
				return false
			}

			baseIndex++
			i++

			continue
		}

		// unicode case
		r, size := utf8.DecodeRune(b[i:])
		if unicode.ToUpper(r) != baseRune {
			return false
		}
		baseIndex++
		i += size
	}

	if baseIndex != len(base) {
		return false
	}

	// all passed: now we should only have blanks
	for i < len(b) {
		if c := b[i]; c < utf8.RuneSelf {
			// fast path for ASCII
			if c != ' ' && c != '\t' {
				return false
			}
			i++

			continue
		}

		// unicode case
		r, size := utf8.DecodeRune(b[i:])
		if !unicode.IsSpace(r) {
			return false
		}

		i += size
	}

	return true
}
