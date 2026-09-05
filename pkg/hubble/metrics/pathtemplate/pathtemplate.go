// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package pathtemplate

import (
	"errors"
	"fmt"
	"strings"
)

// MaxTemplates caps the list, which bounds both the number of distinct "path"
// label values and the cost of a single match.
const MaxTemplates = 100

// MaxTemplateSegments caps a single template's depth. It is what keeps Match's
// split buffer on the stack, so a match never allocates whatever the config
// holds. Raising it later is backwards compatible but costs time on every
// match, since the buffer is zeroed per call.
const MaxTemplateSegments = 32

type segmentKind uint8

const (
	// segmentLiteral matches one path segment byte for byte.
	segmentLiteral segmentKind = iota
	// segmentSingle is "{name}" and matches one non-empty path segment.
	segmentSingle
	// segmentTail is "{name...}" and matches every remaining path segment.
	segmentTail
)

type segment struct {
	kind segmentKind
	// literal is only set for segmentLiteral.
	literal string
}

type template struct {
	raw      string
	segments []segment
	hasTail  bool
}

// Matcher is an ordered list of compiled path templates. It never changes after
// Compile returns, so it is safe to use from several goroutines and safe to
// replace as a whole on a config reload.
type Matcher struct {
	templates []template
	// maxSegments is the longest template. Match never splits a path further,
	// since no template can tell paths apart beyond that point.
	maxSegments int
}

// Shadow describes a template that can never match, because a template before
// it already matches every path it would.
type Shadow struct {
	Index      int
	Template   string
	ByIndex    int
	ByTemplate string
}

// Compile turns templates into a Matcher, keeping the order given. The list
// needs at least one entry and at most MaxTemplates, no template may be deeper
// than MaxTemplateSegments, and every bad template is reported in one error.
//
// Two templates that match the same set of paths are rejected as duplicates,
// even when they differ in placeholder names, because the second could never
// match. A broad template hiding a narrower one is not a duplicate. See
// Matcher.Shadowed for that.
//
// Compile either fails or keeps every entry at the index it was given, so a
// successful Matcher holds exactly the configured list. Callers rely on that to
// check an "onMiss" value against the templates, and to work out which
// templates a reload removed.
func Compile(templates []string) (*Matcher, error) {
	if len(templates) == 0 {
		return nil, errors.New("no templates configured")
	}
	if len(templates) > MaxTemplates {
		return nil, fmt.Errorf("%d templates configured, at most %d are supported", len(templates), MaxTemplates)
	}

	m := &Matcher{templates: make([]template, 0, len(templates))}
	firstSeen := make(map[string]int, len(templates))
	var errs []error

	for i, raw := range templates {
		t, err := compileTemplate(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("templates[%d] (%q): %w", i, raw, err))
			continue
		}
		key := t.matchSet()
		if j, dup := firstSeen[key]; dup {
			errs = append(errs, fmt.Errorf("templates[%d] (%q): matches the same paths as templates[%d] (%q)", i, raw, j, templates[j]))
			continue
		}
		firstSeen[key] = i
		m.templates = append(m.templates, t)
		if len(t.segments) > m.maxSegments {
			m.maxSegments = len(t.segments)
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return m, nil
}

// Match returns the first template that matches path, in configured order, and
// whether one matched. The string returned is the template, placeholders and
// all.
//
// Pass url.URL.EscapedPath, not url.URL.Path. url.Parse percent-decodes Path,
// so an encoded "/" becomes a real separator and a request can split a path
// where the operator never meant it to. EscapedPath is not the raw bytes off
// the wire either, it re-encodes anything not already valid in a path, so a
// segment holding a "{" arrives as "%7B" and the template has to spell it the
// same way.
//
// Match does no other clean-up. Envoy normalizes the path before Hubble records
// it, unless http-normalize-path is turned off.
//
// A nil Matcher matches nothing.
func (m *Matcher) Match(path string) (string, bool) {
	if m == nil {
		return "", false
	}

	// Split at most maxSegments+1 times. No template looks past segment
	// maxSegments-1, so splitting further cannot change the answer, and a path
	// with thousands of segments costs the same as a short one. Splitting all of
	// it would let the client set how much work a match takes. MaxTemplateSegments
	// bounds maxSegments, so the buffer always fits on the stack.
	limit := m.maxSegments + 1
	var buf [MaxTemplateSegments + 1]string
	segments := buf[:0]

	rest := path
	for len(segments) < limit-1 {
		i := strings.IndexByte(rest, '/')
		if i < 0 {
			break
		}
		segments = append(segments, rest[:i])
		rest = rest[i+1:]
	}
	segments = append(segments, rest)

	// complete says whether segments holds the whole path. If not, the last
	// element is the unsplit remainder and the path has more segments than any
	// template can tell apart.
	complete := len(segments) < limit

	for i := range m.templates {
		if m.templates[i].match(segments, complete) {
			return m.templates[i].raw, true
		}
	}
	return "", false
}

func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return len(m.templates)
}

// Shadowed returns the templates that can never match, because an earlier
// template already matches every path they would. Compile accepts these, since
// the order is the operator's to choose, but it nearly always means the list is
// in the wrong order, and a hit-or-miss counter will not show it because the
// earlier template keeps matching.
//
// The list is not exhaustive. A template hidden only by several earlier
// templates put together is not reported.
func (m *Matcher) Shadowed() []Shadow {
	if m == nil {
		return nil
	}
	var shadows []Shadow
	for i := range m.templates {
		for j := range i {
			if m.templates[j].covers(&m.templates[i]) {
				shadows = append(shadows, Shadow{
					Index:      i,
					Template:   m.templates[i].raw,
					ByIndex:    j,
					ByTemplate: m.templates[j].raw,
				})
				break
			}
		}
	}
	return shadows
}

// match reports whether the template matches a path already split on "/".
// complete says whether path holds every segment. If not, path holds
// maxSegments+1 elements and the last one is the unsplit remainder.
func (t *template) match(path []string, complete bool) bool {
	if t.hasTail {
		// The tail takes whatever is left and may be empty, so
		// "/static/{rest...}" matches "/static/" but not "/static". A path that
		// was not fully split always has more segments than any template.
		if complete && len(path) < len(t.segments) {
			return false
		}
	} else if !complete || len(path) != len(t.segments) {
		return false
	}

	for i, seg := range t.segments {
		switch seg.kind {
		case segmentTail:
			return true
		case segmentSingle:
			if path[i] == "" {
				return false
			}
		case segmentLiteral:
			if path[i] != seg.literal {
				return false
			}
		}
	}
	return true
}

// covers reports whether every path u matches is also matched by t.
func (t *template) covers(u *template) bool {
	if t.hasTail {
		// t matches any path of at least len(t.segments) segments, and the
		// shortest path u matches has len(u.segments).
		if len(u.segments) < len(t.segments) {
			return false
		}
	} else if u.hasTail || len(u.segments) != len(t.segments) {
		// Without a tail t matches one path length only, so it cannot cover a
		// tail, which matches many.
		return false
	}

	for i, seg := range t.segments {
		if seg.kind == segmentTail {
			return true
		}
		if !seg.covers(u.segments[i]) {
			return false
		}
	}
	return true
}

// covers reports whether every value s matches is also matched by seg.
func (seg segment) covers(s segment) bool {
	switch seg.kind {
	case segmentLiteral:
		return s.kind == segmentLiteral && s.literal == seg.literal
	case segmentSingle:
		// A placeholder needs a non-empty segment, so it covers any literal but
		// the empty one.
		return s.kind == segmentSingle || (s.kind == segmentLiteral && s.literal != "")
	}
	return false
}

// matchSet returns the template with placeholder names stripped, so two
// templates matching the same paths share a key. A literal segment can never
// hold a brace, so it cannot collide with a stripped placeholder.
func (t *template) matchSet() string {
	var b strings.Builder
	b.Grow(len(t.raw))
	for i, seg := range t.segments {
		if i > 0 {
			b.WriteByte('/')
		}
		switch seg.kind {
		case segmentLiteral:
			b.WriteString(seg.literal)
		case segmentSingle:
			b.WriteString("{}")
		case segmentTail:
			b.WriteString("{...}")
		}
	}
	return b.String()
}

func compileTemplate(raw string) (template, error) {
	if raw == "" {
		return template{}, errors.New("template is empty")
	}
	// Paths come from a parsed URL and always start with "/".
	if raw[0] != '/' {
		return template{}, errors.New("template must start with '/'")
	}

	parts := strings.Split(raw, "/")
	if len(parts) > MaxTemplateSegments {
		return template{}, fmt.Errorf("template has %d segments, at most %d are supported", len(parts), MaxTemplateSegments)
	}
	segments := make([]segment, len(parts))
	for i, part := range parts {
		seg, err := compileSegment(part)
		if err != nil {
			return template{}, fmt.Errorf("segment %d (%q): %w", i, part, err)
		}
		if seg.kind == segmentTail && i != len(parts)-1 {
			return template{}, fmt.Errorf("segment %d (%q): a %q placeholder must be last", i, part, "{name...}")
		}
		segments[i] = seg
	}

	return template{
		raw:      raw,
		segments: segments,
		hasTail:  segments[len(segments)-1].kind == segmentTail,
	}, nil
}

func compileSegment(s string) (segment, error) {
	if !strings.ContainsAny(s, "{}") {
		return segment{kind: segmentLiteral, literal: s}, nil
	}

	name, ok := strings.CutPrefix(s, "{")
	if !ok {
		return segment{}, errors.New("a placeholder must span a whole segment")
	}
	name, ok = strings.CutSuffix(name, "}")
	if !ok {
		return segment{}, errors.New("a placeholder must span a whole segment")
	}

	// ":" is kept free for a future "{name:pattern}". Checked before the braces
	// below so that a pattern holding braces reports the reserved syntax rather
	// than a malformed segment.
	if strings.Contains(name, ":") {
		return segment{}, errors.New("patterns in placeholders are not supported")
	}
	if strings.ContainsAny(name, "{}") {
		return segment{}, errors.New("a placeholder must span a whole segment")
	}

	kind := segmentSingle
	if rest, isTail := strings.CutSuffix(name, "..."); isTail {
		name = rest
		kind = segmentTail
	}

	if !validPlaceholderName(name) {
		return segment{}, fmt.Errorf("invalid placeholder name %q, expected [A-Za-z_][A-Za-z0-9_]*", name)
	}

	return segment{kind: kind}, nil
}

func validPlaceholderName(name string) bool {
	if name == "" {
		return false
	}
	for i := range len(name) {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case i > 0 && c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}
