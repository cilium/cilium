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

// Package licenseclassifier provides methods to identify the open source
// license that most closely matches an unknown license.
package licenseclassifier

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"html"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"

	"github.com/google/licenseclassifier/stringclassifier"
	"github.com/google/licenseclassifier/stringclassifier/searchset"
)

// DefaultConfidenceThreshold is the minimum confidence percentage we're willing to accept in order
// to say that a match is good.
const DefaultConfidenceThreshold = 0.80

var (
	// Normalizers is a list of functions that get applied to the strings
	// before they are registered with the string classifier.
	Normalizers = []stringclassifier.NormalizeFunc{
		html.UnescapeString,
		removeShebangLine,
		RemoveNonWords,
		NormalizeEquivalentWords,
		NormalizePunctuation,
		strings.ToLower,
		removeIgnorableTexts,
		stringclassifier.FlattenWhitespace,
		strings.TrimSpace,
	}

	// commonLicenseWords are words that are common to all known licenses.
	// If an unknown text doesn't have at least one of these, then we can
	// ignore it.
	commonLicenseWords = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bcode\b`),
		regexp.MustCompile(`(?i)\blicense\b`),
		regexp.MustCompile(`(?i)\boriginal\b`),
		regexp.MustCompile(`(?i)\brights\b`),
		regexp.MustCompile(`(?i)\bsoftware\b`),
		regexp.MustCompile(`(?i)\bterms\b`),
		regexp.MustCompile(`(?i)\bversion\b`),
		regexp.MustCompile(`(?i)\bwork\b`),
	}
)

// License is a classifier pre-loaded with known open source licenses.
type License struct {
	c *stringclassifier.Classifier

	// Threshold is the lowest confidence percentage acceptable for the
	// classifier.
	Threshold float64

	// archive is a function that must return the contents of the license archive.
	// When archive is nil, ReadLicenseFile(LicenseFile) is used to retrieve the
	// contents.
	archive func() ([]byte, error)
}

// OptionFunc set options on a License struct.
type OptionFunc func(l *License) error

// Archive is an OptionFunc to specify the location of the license archive file.
func Archive(f string) OptionFunc {
	return func(l *License) error {
		l.archive = func() ([]byte, error) { return ReadLicenseFile(f) }
		return nil
	}
}

// ArchiveBytes is an OptionFunc that provides the contents of the license archive file.
// The caller must not overwrite the contents of b as it is not copied.
func ArchiveBytes(b []byte) OptionFunc {
	return func(l *License) error {
		l.archive = func() ([]byte, error) { return b, nil }
		return nil
	}
}

// ArchiveFunc is an OptionFunc that provides a function that must return the contents
// of the license archive file.
func ArchiveFunc(f func() ([]byte, error)) OptionFunc {
	return func(l *License) error {
		l.archive = f
		return nil
	}
}

// New creates a license classifier and pre-loads it with known open source licenses.
func New(threshold float64, options ...OptionFunc) (*License, error) {
	classifier := &License{
		c:         stringclassifier.New(threshold, Normalizers...),
		Threshold: threshold,
	}

	for _, o := range options {
		err := o(classifier)
		if err != nil {
			return nil, fmt.Errorf("error setting option %v: %v", o, err)
		}
	}

	if err := classifier.registerLicenses(); err != nil {
		return nil, fmt.Errorf("cannot register licenses from archive: %v", err)
	}
	return classifier, nil
}

// NewWithForbiddenLicenses creates a license classifier and pre-loads it with
// known open source licenses which are forbidden.
func NewWithForbiddenLicenses(threshold float64, options ...OptionFunc) (*License, error) {
	opts := []OptionFunc{Archive(ForbiddenLicenseArchive)}
	opts = append(opts, options...)
	return New(threshold, opts...)
}

// WithinConfidenceThreshold returns true if the confidence value is above or
// equal to the confidence threshold.
func (c *License) WithinConfidenceThreshold(conf float64) bool {
	return conf > c.Threshold || math.Abs(conf-c.Threshold) < math.SmallestNonzeroFloat64
}

// NearestMatch returns the "nearest" match to the given set of known licenses.
// Returned are the name of the license, and a confidence percentage indicating
// how confident the classifier is in the result.
func (c *License) NearestMatch(contents string) *stringclassifier.Match {
	if !c.hasCommonLicenseWords(contents) {
		return nil
	}
	m := c.c.NearestMatch(contents)
	m.Name = strings.TrimSuffix(m.Name, ".header")
	return m
}

// MultipleMatch matches all licenses within an unknown text.
func (c *License) MultipleMatch(contents string, includeHeaders bool) stringclassifier.Matches {
	norm := normalizeText(contents)
	if !c.hasCommonLicenseWords(norm) {
		return nil
	}

	m := make(map[stringclassifier.Match]bool)
	var matches stringclassifier.Matches
	for _, v := range c.c.MultipleMatch(norm) {
		if !c.WithinConfidenceThreshold(v.Confidence) {
			continue
		}

		if !includeHeaders && strings.HasSuffix(v.Name, ".header") {
			continue
		}

		v.Name = strings.TrimSuffix(v.Name, ".header")
		if re, ok := forbiddenRegexps[v.Name]; ok && !re.MatchString(norm) {
			continue
		}
		if _, ok := m[*v]; !ok {
			m[*v] = true
			matches = append(matches, v)
		}
	}
	sort.Sort(matches)
	return matches
}

func normalizeText(s string) string {
	for _, n := range Normalizers {
		s = n(s)
	}
	return s
}

// hasCommonLicenseWords returns true if the unknown text has at least one word
// that's common to all licenses.
func (c *License) hasCommonLicenseWords(s string) bool {
	for _, re := range commonLicenseWords {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

type archivedValue struct {
	name       string
	normalized string
	set        *searchset.SearchSet
}

// registerLicenses loads all known licenses and adds them to c as known values
// for comparison. The allocated space after ingesting the 'licenses.db'
// archive is ~167M.
func (c *License) registerLicenses() error {
	var contents []byte
	var err error
	if c.archive == nil {
		contents, err = ReadLicenseFile(LicenseArchive)
	} else {
		contents, err = c.archive()
	}
	if err != nil {
		return err
	}

	reader := bytes.NewReader(contents)
	gr, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	var muVals sync.Mutex
	var vals []archivedValue
	for i := 0; ; i++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		name := strings.TrimSuffix(hdr.Name, ".txt")

		// Read normalized value.
		var b bytes.Buffer
		if _, err := io.Copy(&b, tr); err != nil {
			return err
		}
		normalized := b.String()
		b.Reset()

		// Read precomputed hashes.
		hdr, err = tr.Next()
		if err != nil {
			return err
		}

		if _, err := io.Copy(&b, tr); err != nil {
			return err
		}

		var set searchset.SearchSet
		searchset.Deserialize(&b, &set)

		muVals.Lock()
		vals = append(vals, archivedValue{name, normalized, &set})
		muVals.Unlock()
	}

	for _, v := range vals {
		if err = c.c.AddPrecomputedValue(v.name, v.normalized, v.set); err != nil {
			return err
		}
	}
	return nil
}

// endOfLicenseText is text commonly associated with the end of a license. We
// can remove text that occurs after it.
var endOfLicenseText = []string{
	"END OF TERMS AND CONDITIONS",
}

// TrimExtraneousTrailingText removes text after an obvious end of the license
// and does not include substantive text of the license.
func TrimExtraneousTrailingText(s string) string {
	for _, e := range endOfLicenseText {
		if i := strings.LastIndex(s, e); i != -1 {
			return s[:i+len(e)]
		}
	}
	return s
}

var copyrightRE = regexp.MustCompile(`(?m)(?i:Copyright)\s+(?i:©\s+|\(c\)\s+)?(?:\d{2,4})(?:[-,]\s*\d{2,4})*,?\s*(?i:by)?\s*(.*?(?i:\s+Inc\.)?)[.,]?\s*(?i:All rights reserved\.?)?\s*$`)

// CopyrightHolder finds a copyright notification, if it exists, and returns
// the copyright holder.
func CopyrightHolder(contents string) string {
	matches := copyrightRE.FindStringSubmatch(contents)
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}

var publicDomainRE = regexp.MustCompile("(?i)(this file )?is( in the)? public domain")

// HasPublicDomainNotice performs a simple regex over the contents to see if a
// public domain notice is in there. As you can imagine, this isn't 100%
// definitive, but can be useful if a license match isn't found.
func (c *License) HasPublicDomainNotice(contents string) bool {
	return publicDomainRE.FindString(contents) != ""
}

// ignorableTexts is a list of lines at the start of the string we can remove
// to get a cleaner match.
var ignorableTexts = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^(?:the )?mit license(?: \(mit\))?$`),
	regexp.MustCompile(`(?i)^(?:new )?bsd license$`),
	regexp.MustCompile(`(?i)^copyright and permission notice$`),
	regexp.MustCompile(`(?i)^copyright (\(c\) )?(\[yyyy\]|\d{4})[,.]? .*$`),
	regexp.MustCompile(`(?i)^(all|some) rights reserved\.?$`),
	regexp.MustCompile(`(?i)^@license$`),
	regexp.MustCompile(`^\s*$`),
}

// removeIgnorableTexts removes common text, which is not important for
// classification, that shows up before the body of the license.
func removeIgnorableTexts(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	var start int
	for ; start < len(lines); start++ {
		line := strings.TrimSpace(lines[start])
		var matches bool
		for _, re := range ignorableTexts {
			if re.MatchString(line) {
				matches = true
				break
			}
		}
		if !matches {
			break
		}
	}
	end := len(lines)
	if start > end {
		return "\n"
	}
	return strings.Join(lines[start:end], "\n") + "\n"
}

// removeShebangLine removes the '#!...' line if it's the first line in the
// file. Note that if it's the only line in a comment, it won't be removed.
func removeShebangLine(s string) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= 1 || !strings.HasPrefix(lines[0], "#!") {
		return s
	}

	return strings.Join(lines[1:], "\n")
}

// isDecorative returns true if the line is made up purely of non-letter and
// non-digit characters.
func isDecorative(s string) bool {
	for _, c := range s {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			return false
		}
	}
	return true
}

var nonWords = regexp.MustCompile("[[:punct:]]+")

// RemoveNonWords removes non-words from the string.
func RemoveNonWords(s string) string {
	return nonWords.ReplaceAllString(s, " ")
}

// interchangeablePunctutation is punctuation that can be normalized.
var interchangeablePunctuation = []struct {
	interchangeable *regexp.Regexp
	substitute      string
}{
	// Hyphen, Dash, En Dash, and Em Dash.
	{regexp.MustCompile(`[-‒–—]`), "-"},
	// Single, Double, Curly Single, and Curly Double.
	{regexp.MustCompile("['\"`‘’“”]"), "'"},
	// Copyright.
	{regexp.MustCompile("©"), "(c)"},
	// Hyphen-separated words.
	{regexp.MustCompile(`(\S)-\s+(\S)`), "${1}-${2}"},
	// Currency and Section. (Different copies of the CDDL use each marker.)
	{regexp.MustCompile("[§¤]"), "(s)"},
	// Middle Dot
	{regexp.MustCompile("·"), "*"},
}

// NormalizePunctuation takes all hyphens and quotes and normalizes them.
func NormalizePunctuation(s string) string {
	for _, iw := range interchangeablePunctuation {
		s = iw.interchangeable.ReplaceAllString(s, iw.substitute)
	}
	return s
}

// interchangeableWords are words we can substitute for a normalized form
// without changing the meaning of the license. See
// https://spdx.org/spdx-license-list/matching-guidelines for the list.
var interchangeableWords = []struct {
	interchangeable *regexp.Regexp
	substitute      string
}{
	{regexp.MustCompile("(?i)Acknowledgment"), "Acknowledgement"},
	{regexp.MustCompile("(?i)Analogue"), "Analog"},
	{regexp.MustCompile("(?i)Analyse"), "Analyze"},
	{regexp.MustCompile("(?i)Artefact"), "Artifact"},
	{regexp.MustCompile("(?i)Authorisation"), "Authorization"},
	{regexp.MustCompile("(?i)Authorised"), "Authorized"},
	{regexp.MustCompile("(?i)Calibre"), "Caliber"},
	{regexp.MustCompile("(?i)Cancelled"), "Canceled"},
	{regexp.MustCompile("(?i)Capitalisations"), "Capitalizations"},
	{regexp.MustCompile("(?i)Catalogue"), "Catalog"},
	{regexp.MustCompile("(?i)Categorise"), "Categorize"},
	{regexp.MustCompile("(?i)Centre"), "Center"},
	{regexp.MustCompile("(?i)Emphasised"), "Emphasized"},
	{regexp.MustCompile("(?i)Favour"), "Favor"},
	{regexp.MustCompile("(?i)Favourite"), "Favorite"},
	{regexp.MustCompile("(?i)Fulfil"), "Fulfill"},
	{regexp.MustCompile("(?i)Fulfilment"), "Fulfillment"},
	{regexp.MustCompile("(?i)Initialise"), "Initialize"},
	{regexp.MustCompile("(?i)Judgment"), "Judgement"},
	{regexp.MustCompile("(?i)Labelling"), "Labeling"},
	{regexp.MustCompile("(?i)Labour"), "Labor"},
	{regexp.MustCompile("(?i)Licence"), "License"},
	{regexp.MustCompile("(?i)Maximise"), "Maximize"},
	{regexp.MustCompile("(?i)Modelled"), "Modeled"},
	{regexp.MustCompile("(?i)Modelling"), "Modeling"},
	{regexp.MustCompile("(?i)Offence"), "Offense"},
	{regexp.MustCompile("(?i)Optimise"), "Optimize"},
	{regexp.MustCompile("(?i)Organisation"), "Organization"},
	{regexp.MustCompile("(?i)Organise"), "Organize"},
	{regexp.MustCompile("(?i)Practise"), "Practice"},
	{regexp.MustCompile("(?i)Programme"), "Program"},
	{regexp.MustCompile("(?i)Realise"), "Realize"},
	{regexp.MustCompile("(?i)Recognise"), "Recognize"},
	{regexp.MustCompile("(?i)Signalling"), "Signaling"},
	{regexp.MustCompile("(?i)Sub[- ]license"), "Sublicense"},
	{regexp.MustCompile("(?i)Utilisation"), "Utilization"},
	{regexp.MustCompile("(?i)Whilst"), "While"},
	{regexp.MustCompile("(?i)Wilful"), "Wilfull"},
	{regexp.MustCompile("(?i)Non-commercial"), "Noncommercial"},
	{regexp.MustCompile("(?i)Per cent"), "Percent"},
}

// NormalizeEquivalentWords normalizes equivalent words that are interchangeable.
func NormalizeEquivalentWords(s string) string {
	for _, iw := range interchangeableWords {
		s = iw.interchangeable.ReplaceAllString(s, iw.substitute)
	}
	return s
}
