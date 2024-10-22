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
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Match is the information about a single instance of a detected match.
type Match struct {
	Name            string
	Confidence      float64
	MatchType       string
	Variant         string
	StartLine       int
	EndLine         int
	StartTokenIndex int
	EndTokenIndex   int
}

// Results captures the summary information and matches detected by the
// classifier.
type Results struct {
	Matches         Matches
	TotalInputLines int
}

// Matches is a sortable slice of Match.
type Matches []*Match

// Swap two elements of Matches.
func (d Matches) Swap(i, j int) { d[i], d[j] = d[j], d[i] }
func (d Matches) Len() int      { return len(d) }
func (d Matches) Less(i, j int) bool {
	di, dj := d[i], d[j]
	// Return matches ordered by confidence
	if di.Confidence != dj.Confidence {
		return di.Confidence > dj.Confidence
	}
	// Licenses of same confidence are ordered by their appearance
	if di.StartTokenIndex != dj.StartTokenIndex {
		return di.StartTokenIndex < dj.StartTokenIndex
	}
	// Should never get here, but tiebreak based on the larger license.
	return di.EndTokenIndex > dj.EndTokenIndex
}

// Match reports instances of the supplied content in the corpus.
func (c *Classifier) match(in io.Reader) (Results, error) {
	id, err := tokenizeStream(in, true, c.dict, false)
	if err != nil {
		return Results{}, err
	}

	firstPass := make(map[string]*indexedDocument)
	for l, d := range c.docs {
		sim := id.tokenSimilarity(d)

		if c.tc.traceTokenize(l) {
			c.tc.trace("Token similarity for %s: %.2f", l, sim)
		}

		if sim >= c.threshold {
			firstPass[l] = d
		}
	}

	if len(firstPass) == 0 {
		return Results{
			Matches:         nil,
			TotalInputLines: 0,
		}, nil
	}

	// Perform the expensive work of generating a searchset to look for token runs.
	id.generateSearchSet(c.q)

	var candidates Matches
	candidates = append(candidates, id.Matches...)

	for l, d := range firstPass {
		matches := c.findPotentialMatches(d.s, id.s, c.threshold)
		for _, m := range matches {
			startIndex := m.TargetStart
			endIndex := m.TargetEnd
			conf, startOffset, endOffset := c.score(l, id, d, startIndex, endIndex)
			if conf >= c.threshold && (endIndex-startIndex-startOffset-endOffset) > 0 {
				candidates = append(candidates, &Match{
					Name:            LicenseName(l),
					Variant:         variantName(l),
					MatchType:       detectionType(l),
					Confidence:      conf,
					StartLine:       id.Tokens[startIndex+startOffset].Line,
					EndLine:         id.Tokens[endIndex-endOffset-1].Line,
					StartTokenIndex: startIndex + startOffset,
					EndTokenIndex:   endIndex - endOffset - 1,
				})
			}

		}
	}
	sort.Sort(candidates)
	retain := make([]bool, len(candidates))
	for i, c := range candidates {
		// Filter out overlapping licenses based primarily on confidence. Since
		// the candidates slice is ordered by confidence, we look for overlaps and
		// decide if we retain the record c.

		// For each candidate, only add it to the report unless we have a
		// higher-quality hit that contains these lines. In the case of two
		// licenses having overlap, we consider 'token density' to break ties. If a
		// less confident match of a larger license has more matching tokens than a
		// perfect match of a smaller license, we want to keep that. This handles
		// licenses that include another license as a subtext. NPL contains MPL
		// as a concrete example.

		keep := true
		proposals := make(map[int]bool)
		for j, o := range candidates {
			if j == i {
				break
			}
			// Make sure to only check containment on licenses that are still in consideration at this point.
			if contains(c, o) && retain[j] {
				// The license here can override a previous detection, but that isn't sufficient to be kept
				// on its own. Consider the licenses Xnet, MPL-1.1 and NPL-1.1 in a file that just has MPL-1.1.
				// The confidence rating on NPL-1.1 will cause Xnet to not be retained, which is correct, but it
				// shouldn't be retained if the token confidence for MPL is higher than NPL since the NPL-specific
				// bits are missing.

				ctoks := float64(c.EndTokenIndex - c.StartTokenIndex)
				otoks := float64(o.EndTokenIndex - o.StartTokenIndex)
				cconf := ctoks * c.Confidence
				oconf := otoks * o.Confidence

				// If the two licenses are exactly the same confidence, that means we
				// have an ambiguous detect and should retain both, so the caller can
				// see and resolve the situation.
				if cconf > oconf {
					proposals[j] = false
				} else if oconf > cconf {
					keep = false
				}
			} else if overlaps(c, o) && retain[j] {
				// if the ending and start lines exactly overlap, it's OK to keep both
				if c.StartLine != o.EndLine {
					keep = false
				}
			}

			if !keep {
				break
			}
		}
		if keep {
			retain[i] = true
			for p, v := range proposals {
				retain[p] = v
			}
		}
	}

	var out Matches
	for i, keep := range retain {
		if keep {
			out = append(out, candidates[i])
		}
	}
	return Results{
		Matches:         out,
		TotalInputLines: id.Tokens[len(id.Tokens)-1].Line,
	}, nil
}

// Classifier provides methods for identifying open source licenses in text
// content.
type Classifier struct {
	tc        *TraceConfiguration
	dict      *dictionary
	docs      map[string]*indexedDocument
	threshold float64
	q         int // The value of q for q-grams in this corpus
}

// NewClassifier creates a classifier with an empty corpus.
func NewClassifier(threshold float64) *Classifier {
	classifier := &Classifier{
		tc:        new(TraceConfiguration),
		dict:      newDictionary(),
		docs:      make(map[string]*indexedDocument),
		threshold: threshold,
		q:         computeQ(threshold),
	}
	return classifier
}

// Normalize takes input content and applies the following transforms to aid in
// identifying license content. The return value of this function is
// line-separated text which is the basis for position values returned by the
// classifier.
//
// 1. Breaks up long lines of text. This helps with detecting licenses like in
// TODO(wcn):URL reference
//
// 2. Certain ignorable texts are removed to aid matching blocks of text.
// Introductory lines such as "The MIT License" are removed. Copyright notices
// are removed since the parties are variable and shouldn't impact matching.
//
// It is NOT necessary to call this function to simply identify licenses in a
// file. It should only be called to aid presenting this information to the user
// in context (for example, creating diffs of differences to canonical
// licenses).
//
// It is an invariant of the classifier that calling Match(Normalize(in)) will
// return the same results as Match(in).
func (c *Classifier) Normalize(in []byte) []byte {
	doc, err := tokenizeStream(bytes.NewReader(in), false, c.dict, true)
	if err != nil {
		panic("should not be reachable, since bytes.NewReader().Read() should never fail")
	}

	var buf bytes.Buffer

	switch len(doc.Tokens) {
	case 0:
		return nil
	case 1:
		buf.WriteString(c.dict.getWord(doc.Tokens[0].ID))
		return buf.Bytes()
	}

	prevLine := 1
	buf.WriteString(c.dict.getWord(doc.Tokens[0].ID))
	for _, t := range doc.Tokens[1:] {
		// Only write out an EOL token that incremented the line
		if t.Line == prevLine+1 {
			buf.WriteString(eol)
		}

		// Only write tokens that aren't EOL
		txt := c.dict.getWord(t.ID)

		if txt != eol {
			// Only put a space between tokens if the previous token was on the same
			// line. This prevents spaces after an EOL
			if t.Line == prevLine {
				buf.WriteString(" ")
			}
			buf.WriteString(txt)
		}

		prevLine = t.Line
	}
	return buf.Bytes()
}

// LoadLicenses adds the contents of the supplied directory to the corpus of the
// classifier.
func (c *Classifier) LoadLicenses(dir string) error {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !strings.HasSuffix(path, "txt") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return err
	}

	for _, f := range files {
		relativePath := strings.Replace(f, dir, "", 1)
		sep := fmt.Sprintf("%c", os.PathSeparator)
		segments := strings.Split(relativePath, sep)
		if len(segments) < 3 {
			c.tc.trace("Insufficient segment count for path: %s", relativePath)
			continue
		}
		category, name, variant := segments[1], segments[2], segments[3]
		b, err := ioutil.ReadFile(f)
		if err != nil {
			return err
		}

		c.AddContent(category, name, variant, []byte(string(b)))
	}
	return nil
}

// SetTraceConfiguration installs a tracing configuration for the classifier.
func (c *Classifier) SetTraceConfiguration(in *TraceConfiguration) {
	c.tc = in
	c.tc.init()
}

// Match finds matches within an unknown text. This will not modify the contents
// of the supplied byte slice.
func (c *Classifier) Match(in []byte) Results {
	// Since bytes.NewReader().Read() will never return an error, tokenizeStream
	// will never return an error so it's okay to ignore the return value in this
	// case.
	res, _ := c.MatchFrom(bytes.NewReader(in))
	return res
}

// MatchFrom finds matches within the read content.
func (c *Classifier) MatchFrom(in io.Reader) (Results, error) {
	return c.match(in)
}

func detectionType(in string) string {
	splits := strings.Split(in, fmt.Sprintf("%c", os.PathSeparator))
	return splits[0]
}

func variantName(in string) string {
	splits := strings.Split(in, fmt.Sprintf("%c", os.PathSeparator))
	return splits[2]
}

// LicenseName produces the output name for a license, removing the internal structure
// of the filename in use.
func LicenseName(in string) string {
	splits := strings.Split(in, fmt.Sprintf("%c", os.PathSeparator))
	return splits[1]
}

// contains returns true iff b is completely inside a
func contains(a, b *Match) bool {
	return a.StartLine <= b.StartLine && a.EndLine >= b.EndLine
}

// returns true iff b <= a <= c
func between(a, b, c int) bool {
	return b <= a && a <= c
}

// returns true iff the ranges covered by a and b overlap.
func overlaps(a, b *Match) bool {
	return between(a.StartLine, b.StartLine, b.EndLine) || between(a.EndLine, b.StartLine, b.EndLine)
}
