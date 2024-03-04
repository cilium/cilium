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

// Package classifier provides the implementation of the v2 license classifier.
package classifier

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

type tokenID int // type to ensure safety when manipulating token identifiers.

// token provides detailed information about a single textual token in the document.
type token struct {
	Text     string // normalized text of the token
	Line     int    // line position of this token in the source
	Previous string // for the first token in a line, any previous text.
}

type indexedToken struct {
	Line int     // line position of this token in the source
	ID   tokenID // identifier of the text in the dictionary
}

type indexedDocument struct {
	Norm    string          // The normalized token sequence
	Tokens  []indexedToken  // ordered tokens of the document
	Matches Matches         // these are matches identified while processing the original, untokenized text via regexp matching
	f       *frequencyTable // frequencies computed for this document
	dict    *dictionary     // The corpus dictionary for this document
	s       *searchSet      // The searchset for this document
	runes   []rune
}

func (d *indexedDocument) generateSearchSet(q int) {
	d.s = newSearchSet(d, q)
}

func (d *indexedDocument) size() int {
	return len(d.Tokens)
}

// normalized returns a string of the normalized tokens concatenated with a
// single space. This is used by the diff algorithm.
// TODO: it'd be more efficient to have the diff algorithm work with the raw tokens directly
// and avoid these ephemeral allocations.
func (d *indexedDocument) normalized() string {
	var w strings.Builder
	for i, t := range d.Tokens {
		w.WriteString(d.dict.getWord(t.ID))
		if (i + 1) != d.size() {
			w.WriteString(" ")
		}
	}
	return w.String()
}

func computeQ(threshold float64) int {
	// q is the lower bound for token runs (q-grams) that must exist
	// in content that can be recognized at the specified threshold.
	// Imagine a document with 100 tokens, and a threshold of 80%. This means
	// that in a worst-case scenario, the 20 errors are evenly distributed to
	// create the sortest possible token runs. In this case, there would be
	// a repeating sequence of 4 good tokens and 1 errored token, occurring
	// 20 times. This function returns the minimum token length, or returning
	// a value of 1 if necessary (since a threshold level below 50% would generate
	// a run of 0-length, which is meaningless.)
	if threshold == 1.0 {
		return 10 // avoid divide by 0
	}

	return max(1, int((threshold)/(1.0-threshold)))
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// AddContent incorporates the provided textual content into the classifier for
// matching. This will not modify the supplied content.
func (c *Classifier) AddContent(category, name, variant string, content []byte) {
	// Since bytes.NewReader().Read() will never return an error, tokenizeStream
	// will never return an error so it's okay to ignore the return value in this
	// case.
	doc, _ := tokenizeStream(bytes.NewReader(content), true, c.dict, true)
	c.addDocument(category, name, variant, doc)
}

// addDocument takes a textual document and incorporates it into the classifier for matching.
func (c *Classifier) addDocument(category, name, variant string, id *indexedDocument) {
	// For documents that are part of the corpus, we add them to the dictionary and
	// compute their associated search data eagerly so they are ready for matching against
	// candidates.
	indexName := c.generateDocName(category, name, variant)
	id.generateSearchSet(c.q)
	id.s.origin = indexName
	c.docs[indexName] = id
}

// createTargetIndexedDocument creates an indexed document without adding the
// words to the classifier dictionary. This should be used for matching targets, not
// populating the corpus.
func (c *Classifier) createTargetIndexedDocument(in []byte) *indexedDocument {
	doc, _ := tokenizeStream(bytes.NewReader(in), true, c.dict, false)
	return doc
}

func (c *Classifier) generateDocName(category, name, variant string) string {
	return fmt.Sprintf("%s%c%s%c%s", category, os.PathSeparator, name, os.PathSeparator, variant)
}
func (c *Classifier) getIndexedDocument(category, name, variant string) *indexedDocument {
	return c.docs[c.generateDocName(category, name, variant)]
}

// dictionary is used to intern all the token words encountered in the text corpus.
// words and indices form an inverse mapping relationship. It is just a convenience type
// over a pair of correlated maps.
type dictionary struct {
	words   map[tokenID]string
	indices map[string]tokenID
}

func newDictionary() *dictionary {
	return &dictionary{
		words:   make(map[tokenID]string),
		indices: make(map[string]tokenID),
	}
}

// add inserts the provided word into the dictionary if it does not already exist.
func (d *dictionary) add(word string) tokenID {
	if idx := d.getIndex(word); idx != unknownIndex {
		return idx
	}
	// token IDs start from 1, 0 is reserved for the invalid ID
	idx := tokenID(len(d.words) + 1)
	d.words[idx] = word
	d.indices[word] = idx
	return idx
}

var unknownWord = "UNKNOWN"
var unknownIndex = tokenID(0)

// getIndex returns the index of the supplied word, or 0 if the word is not in the dictionary.
func (d *dictionary) getIndex(word string) tokenID {
	if idx, found := d.indices[word]; found {
		return idx
	}
	return unknownIndex
}

// getWord returns the word associated with the index.
func (d *dictionary) getWord(index tokenID) string {
	if word, found := d.words[index]; found {
		return word
	}
	return unknownWord
}
