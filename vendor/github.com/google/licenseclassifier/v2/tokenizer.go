// Copyright 2020 Google Inc.
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

package classifier

import (
	"html"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var eol = "\n"

func header(in string) bool {
	if len(in) == 0 {
		return false
	}
	p, e := in[:len(in)-1], in[len(in)-1]
	switch e {
	case '.', ':', ')':
		if listMarker[p] {
			if e != ')' {
				return true
			}
		}
		// Check for patterns like 1.2.3
		for _, r := range p {
			if unicode.IsDigit(r) || r == '.' {
				continue
			}
			return false
		}
		return true
	}
	return false
}

var listMarker = func() map[string]bool {
	const allListMarkers = "a b c d e f g h i j k l m n o p q r ii iii iv v vi vii viii ix xi xii xiii xiv xv"
	l := map[string]bool{}
	for _, marker := range strings.Split(allListMarkers, " ") {
		l[marker] = true
	}
	return l
}()

// ignorableTexts is a list of lines at the start of the string we can remove
// to get a cleaner match.
var ignorableTexts = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^(.{1,5})?copyright (\(c\) )?(\[yyyy\]|\d{4})[,.]?.*$`),
	regexp.MustCompile(`(?i)^(.{1,5})?copyright \(c\) \[dates of first publication\].*$`),
	regexp.MustCompile(`(?i)^\d{4}-(\d{2}|[a-z]{3})-\d{2}$`),
}

// tokenizeStream reads bytes from src and produces an indexedDocument of its
// cotent. tokenizeStream will never return an error of its own, it can only
// return an error from the provided Reader. If the provided Reader never
// returns an error, it is safe to assume that tokenizeStream will not return an
// error.
func tokenizeStream(src io.Reader, normalize bool, dict *dictionary, updateDict bool) (*indexedDocument, error) {
	const bufSize = 1024
	// The longest UTF-8 encoded rune is 4 bytes, so we keep enough leftover bytes
	// in the buffer to ensure we never run out of bytes trying to finish
	// constructing a rune. These leftover 4 bytes will be copied to the start of
	// the buffer before additional bytes are read.
	tgt := bufSize - 4

	rbuf := make([]byte, bufSize)
	obuf := make([]byte, 0)
	linebuf := make([]tokenID, 0)
	idx := 0
	line := 1 // 1s-based count
	deferredEOL := false
	deferredWord := false
	// the tokenizer uses a local dictionary to conserve memory while
	// analyzing the input doc to avoid polluting the global dictionary
	ld := newDictionary()

	var doc indexedDocument

	isEOF := func(in error) bool {
		return in == io.EOF || in == io.ErrUnexpectedEOF
	}

	// Read out the stream in chunks
	for {
		// Fill up the buffer with bytes to extract runes from
		// idx is offset to hold any bytes left over from previous reads
		n, err := io.ReadFull(src, rbuf[idx:])
		if isEOF(err) {
			// There are no more bytes to read, so we must now consume all bytes in the
			// buffer.
			tgt = idx + n
		} else if err != nil {
			return nil, err
		}

		for idx = 0; idx < tgt; {
			r, n := utf8.DecodeRune(rbuf[idx:])
			idx += n

			if r == '\n' {
				// Deal with carriage return

				// If we are in a word (len(obuf) > 0)and the last rune is a -
				// strike that rune and keep accumulating.
				// Otherwise we treat it like a space and
				// flush the word

				if len(obuf) > 0 {
					if obuf[len(obuf)-1] == '-' {
						obuf = obuf[0 : len(obuf)-1]
						deferredEOL = true
						continue
					}

					// Append the word fragment to the line buffer
					linebuf = append(linebuf, flushBuf(len(linebuf), obuf, normalize, ld))
				}

				// If there is something in the line to process, do so now
				if len(linebuf) > 0 {
					appendToDoc(&doc, dict, line, linebuf, ld, normalize, updateDict, linebuf)
					linebuf = nil
					obuf = nil
				}
				if !normalize {
					tokID := dict.getIndex(eol)
					if tokID == unknownIndex {
						tokID = dict.add(eol)
					}
					doc.Tokens = append(doc.Tokens, indexedToken{
						ID:   tokID,
						Line: line})
				}
				line++
				continue
			}

			if len(obuf) == 0 {
				if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '&' || r == '(' {
					// Number or word character starts an interesting word
					// Now we slurp up all non-space runes and aggregate it as
					// a single word

					// Buffer the initial token, normalizing to lower case if needed
					if normalize {
						r = unicode.ToLower(r)
					}
					obuf = utf8.AppendRune(obuf, r)
				}
				continue
			}

			// At this point, len(obuf) > 0 and we are accumulating more runes
			// to complete a word.
			if unicode.IsSpace(r) {
				// If we have a deferred EOL, we need to pick up a non-space character
				// to resume the hyphenated word, so we just consume spaces until that
				// happens
				if deferredEOL {
					continue
				}

				// This is a space between word characters, so we assemble the word as a
				// token and flush it out.
				idx -= n

				linebuf = append(linebuf, flushBuf(len(linebuf), obuf, normalize, ld))
				if deferredWord {
					appendToDoc(&doc, dict, line, linebuf, ld, normalize, updateDict, linebuf)
					linebuf = nil
					deferredWord = false
					// Increment the line count now so the remainder token is credited
					// to the previous line number.
					line++
				}
				obuf = make([]byte, 0)
				continue
			}

			if deferredEOL {
				deferredEOL = false
				deferredWord = true
			}
			// perform token mappings for punctuation to emulate
			// normalizePunctuation. this returns a string and each rune needs to be
			// injected.
			if rep, found := punctuationMappings[r]; found {
				for _, t := range rep {
					obuf = utf8.AppendRune(obuf, unicode.ToLower(t))
				}
				continue
			}

			// if it's not punctuation, lowercase and buffer the token
			obuf = utf8.AppendRune(obuf, unicode.ToLower(r))
		}

		// Break out if we have consumed all read bytes
		if isEOF(err) {
			break
		}

		// Copy the unconsumed bytes at the end of the buffer to the start
		// of the buffer so the next read appends after them.
		n = copy(rbuf, rbuf[idx:])
		idx = n
	}

	// Process the remaining bytes in the buffer
	if len(obuf) > 0 {
		linebuf = append(linebuf, flushBuf(len(linebuf), obuf, normalize, ld))
	}
	if len(linebuf) > 0 {
		appendToDoc(&doc, dict, line, linebuf, ld, normalize, updateDict, linebuf)
	}

	doc.dict = dict
	doc.generateFrequencies()
	doc.runes = diffWordsToRunes(&doc, 0, doc.size())
	doc.Norm = doc.normalized()
	return &doc, nil
}

func appendToDoc(doc *indexedDocument, dict *dictionary, line int, in []tokenID, ld *dictionary, normalize bool, updateDict bool, linebuf []tokenID) {
	tokens, m := stringifyLineBuf(dict, line, linebuf, ld, normalize, updateDict)
	if tokens != nil {
		doc.Tokens = append(doc.Tokens, tokens...)
	} else if m != nil {
		doc.Matches = append(doc.Matches, m)
	}
}

func stringifyLineBuf(dict *dictionary, line int, in []tokenID, ld *dictionary, normalize bool, updateDict bool) ([]indexedToken, *Match) {
	if len(in) == 0 {
		return nil, nil
	}
	var sb strings.Builder
	for i, r := range in {
		out := ld.getWord(r)
		if out == "" {
			continue
		}
		sb.WriteString(out)
		if i < len(in)-1 {
			sb.WriteByte(' ')
		}
	}

	out := sb.String()

	for _, re := range ignorableTexts {
		if re.MatchString(out) {
			return nil, &Match{Name: "Copyright", MatchType: "Copyright", Confidence: 1.0, StartLine: line, EndLine: line}
		}
	}

	var tokens []indexedToken
	for i, r := range in {
		txt := cleanupToken(i, ld.getWord(r), normalize)
		if txt != "" {
			var tokID tokenID
			if updateDict {
				tokID = dict.add(txt)
			} else {
				tokID = dict.getIndex(txt)
			}
			tokens = append(tokens, indexedToken{
				Line: line,
				ID:   tokID,
			})
		}
	}

	return tokens, nil
}

func normalizeToken(in string) string {
	// This performs some preprocessing on the token.
	// This is different than cleanupToken in that fixups here
	// are not exact match on the token.
	// Normalizing URLs from https to http is an example of a fix applied
	// here.
	return strings.ReplaceAll(in, "https", "http")
}

func flushBuf(pos int, obuf []byte, normalizeWord bool, ld *dictionary) tokenID {
	// clean up the contents of the rune buffer
	token := string(obuf)
	// escape sequences can occur anywhere in the string, not just the beginning
	// so always attempt to unescape the word's content.
	token = html.UnescapeString(token)

	clean := normalizeToken(token)

	return ld.add(clean)
}

func cleanupToken(pos int, in string, normalizeWord bool) string {
	r, _ := utf8.DecodeRuneInString(in)
	var out strings.Builder
	if pos == 0 && header(in) {
		return ""
	}

	if !unicode.IsLetter(r) {
		if unicode.IsDigit(r) {
			// Based on analysis of the license corpus, the characters that are
			// significant are numbers, periods, and dashes. Anything else can be
			// safely discarded, and helps avoid matching failures due to inconsistent
			// whitespacing and formatting.
			for _, c := range in {
				if unicode.IsDigit(c) || c == '.' || c == '-' {
					out.WriteRune(c)
				}
			}

			// Numbers should not end in a .  since that doesn't indicate a version
			// number, but usually an end of a line.
			res := out.String()
			for strings.HasSuffix(res, ".") {
				res = res[0 : len(res)-1]
			}
			return res
		}
	}

	// Remove internal hyphenization or URL constructs to better normalize strings
	// for matching.

	for _, c := range in {
		if unicode.IsLetter(c) {
			out.WriteRune(c)
		}
	}

	tok := out.String()
	if !normalizeWord {
		return tok
	}

	if iw, ok := interchangeableWords[tok]; ok && normalizeWord {
		return iw
	}
	return tok
}

var interchangeableWords = map[string]string{
	"analyse":         "analyze",
	"artefact":        "artifact",
	"authorisation":   "authorization",
	"authorised":      "authorized",
	"calibre":         "caliber",
	"cancelled":       "canceled",
	"capitalisations": "capitalizations",
	"catalogue":       "catalog",
	"categorise":      "categorize",
	"centre":          "center",
	"emphasised":      "emphasized",
	"favour":          "favor",
	"favourite":       "favorite",
	"fulfil":          "fulfill",
	"fulfilment":      "fulfillment",
	"https":           "http",
	"initialise":      "initialize",
	"judgment":        "judgement",
	"labelling":       "labeling",
	"labour":          "labor",
	"licence":         "license",
	"maximise":        "maximize",
	"modelled":        "modeled",
	"modelling":       "modeling",
	"offence":         "offense",
	"optimise":        "optimize",
	"organisation":    "organization",
	"organise":        "organize",
	"practise":        "practice",
	"programme":       "program",
	"realise":         "realize",
	"recognise":       "recognize",
	"signalling":      "signaling",
	"utilisation":     "utilization",
	"whilst":          "while",
	"wilful":          "wilfull",
	// TODO: These three need tokenizer magic
	"non commercial": "noncommercial",
	"per cent":       "percent",
	"sub license":    "sublicense",
}

var punctuationMappings = map[rune]string{
	'-': "-",
	'‒': "-",
	'–': "-",
	'—': "-",
	'‐': "-",
	'©': "(c)",
	'§': "(s)",
	'¤': "(s)",
	'·': " ",
	'*': " ",
}
