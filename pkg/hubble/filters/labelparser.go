// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// translateSelector takes a label selector with colon-based source prefixes
// and translates it to a valid k8s label selector with dot-based prefixes,
// i.e. "k8s:foo in (bar, baz)" becomes "k8s.foo in (bar, baz)".
// It also makes sure that bare keys without an explicit source will get an
// `any` source prefix.
func translateSelector(selector string) (string, error) {
	out := &strings.Builder{}
	in := strings.NewReader(selector)

	for in.Len() > 0 {
		err := advanceToNextKey(in, out)
		if err != nil {
			return "", err
		}
		err = translateKey(in, out)
		if err != nil {
			return "", err
		}
		err = advanceToNextSelector(in, out)
		if err != nil {
			return "", err
		}
	}
	return out.String(), nil
}

// advanceToNextKey scans from the beginning of a selector to the next
// key and writes everything before the start of the key from in to out.
func advanceToNextKey(in *strings.Reader, out *strings.Builder) error {
	for {
		r, _, err := in.ReadRune()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if !unicode.IsSpace(r) && r != '!' {
			return in.UnreadRune()
		}
		out.WriteRune(r)
	}
}

// translateKey takes a reader that point to the start of a key. It reads
// until the end of the key and writes the translated key (with dot prefixes
// instead of colon-based source prefixes) to out
func translateKey(in *strings.Reader, out *strings.Builder) error {
	key := &strings.Builder{}
	defer func() {
		ckey := key.String()
		if !strings.Contains(ckey, ":") {
			ckey = fmt.Sprintf("any:%s", ckey)
		}
		ckey = strings.Replace(ckey, ":", ".", 1)
		out.WriteString(ckey)
	}()
	for {
		r, _, err := in.ReadRune()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if unicode.IsSpace(r) || r == '=' || r == '!' || r == ',' {
			return in.UnreadRune()
		}
		key.WriteRune(r)
	}
}

// advanceToNextSelector takes a read that points to the end of a key and will
// advance the reader to the beginning of the next selector and writes everything
// it scans to out.
func advanceToNextSelector(in *strings.Reader, out *strings.Builder) error {
	nesting := 0
	for {
		r, _, err := in.ReadRune()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch r {
		case '(':
			nesting++
		case ')':
			nesting--
		}
		out.WriteRune(r)
		if r == ',' && nesting == 0 {
			return nil
		}
	}
}
