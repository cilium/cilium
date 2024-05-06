// Copyright 2017 Google Inc.
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

// Package tokenizer converts a text into a stream of tokens.
package tokenizer

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"sort"
	"unicode"
	"unicode/utf8"
)

// Token is a non-whitespace sequence (i.e., word or punctuation) in the
// original string. This is not meant for use outside of this package.
type token struct {
	Text   string
	Offset int
}

// Tokens is a list of Token objects.
type Tokens []*token

// newToken creates a new token object with an invalid (negative) offset, which
// will be set before the token's used.
func newToken() *token {
	return &token{Offset: -1}
}

// Tokenize converts a string into a stream of tokens.
func Tokenize(s string) (toks Tokens) {
	tok := newToken()
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case unicode.IsSpace(r):
			if tok.Offset >= 0 {
				toks = append(toks, tok)
				tok = newToken()
			}
		case unicode.IsPunct(r):
			if tok.Offset >= 0 {
				toks = append(toks, tok)
				tok = newToken()
			}
			toks = append(toks, &token{
				Text:   string(r),
				Offset: i,
			})
		default:
			if tok.Offset == -1 {
				tok.Offset = i
			}
			tok.Text += string(r)
		}
		i += size
	}
	if tok.Offset != -1 {
		// Add any remaining token that wasn't yet included in the list.
		toks = append(toks, tok)
	}
	return toks
}

// GenerateHashes generates hashes for "size" length substrings. The
// "stringifyTokens" call takes a long time to run, so not all substrings have
// hashes, i.e. we skip some of the smaller substrings.
func (t Tokens) GenerateHashes(h Hash, size int) ([]uint32, TokenRanges) {
	if size == 0 {
		return nil, nil
	}

	var css []uint32
	var tr TokenRanges
	for offset := 0; offset+size <= len(t); offset += size / 2 {
		var b bytes.Buffer
		t.stringifyTokens(&b, offset, size)
		cs := crc32.ChecksumIEEE(b.Bytes())
		css = append(css, cs)
		tr = append(tr, &TokenRange{offset, offset + size})
		h.add(cs, offset, offset+size)
		if size <= 1 {
			break
		}
	}

	return css, tr
}

// stringifyTokens serializes a sublist of tokens into a bytes buffer.
func (t Tokens) stringifyTokens(b *bytes.Buffer, offset, size int) {
	for j := offset; j < offset+size; j++ {
		if j != offset {
			b.WriteRune(' ')
		}
		b.WriteString(t[j].Text)
	}
}

// TokenRange indicates the range of tokens that map to a particular checksum.
type TokenRange struct {
	Start int
	End   int
}

func (t *TokenRange) String() string {
	return fmt.Sprintf("[%v, %v)", t.Start, t.End)
}

// TokenRanges is a list of TokenRange objects. The chance that two different
// strings map to the same checksum is very small, but unfortunately isn't
// zero, so we use this instead of making the assumption that they will all be
// unique.
type TokenRanges []*TokenRange

func (t TokenRanges) Len() int           { return len(t) }
func (t TokenRanges) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }
func (t TokenRanges) Less(i, j int) bool { return t[i].Start < t[j].Start }

// CombineUnique returns the combination of both token ranges with no duplicates.
func (t TokenRanges) CombineUnique(other TokenRanges) TokenRanges {
	if len(other) == 0 {
		return t
	}
	if len(t) == 0 {
		return other
	}

	cu := append(t, other...)
	sort.Sort(cu)

	if len(cu) == 0 {
		return nil
	}

	res := TokenRanges{cu[0]}
	for prev, i := cu[0], 1; i < len(cu); i++ {
		if prev.Start != cu[i].Start || prev.End != cu[i].End {
			res = append(res, cu[i])
			prev = cu[i]
		}
	}
	return res
}

// Hash is a map of the hashes of a section of text to the token range covering that text.
type Hash map[uint32]TokenRanges

// add associates a token range, [start, end], to a checksum.
func (h Hash) add(checksum uint32, start, end int) {
	ntr := &TokenRange{Start: start, End: end}
	if r, ok := h[checksum]; ok {
		for _, tr := range r {
			if tr.Start == ntr.Start && tr.End == ntr.End {
				// The token range already exists at this
				// checksum. No need to re-add it.
				return
			}
		}
	}
	h[checksum] = append(h[checksum], ntr)
}
