// Package stringutil contains utilities for dealing with strings.
package stringutil

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// AllUnique returns true if all items of strs are unique.
func AllUnique(strs []string) (ok bool) {
	set := NewSet()
	for _, s := range strs {
		if set.Has(s) {
			return false
		}

		set.Add(s)
	}

	return true
}

// CloneSliceOrEmpty returns the copy of strs or empty strings slice if strs is
// a nil slice.
func CloneSliceOrEmpty(strs []string) (clone []string) {
	return append([]string{}, strs...)
}

// CloneSlice returns the exact copy of strs.
func CloneSlice(strs []string) (clone []string) {
	if strs == nil {
		return nil
	}

	return CloneSliceOrEmpty(strs)
}

// Coalesce returns the first non-empty string.  It is named after the function
// COALESCE in SQL except that since strings in Go are non-nullable, it uses an
// empty string as a NULL value.  If strs or all it's elements are empty, it
// returns an empty string.
func Coalesce(strs ...string) (res string) {
	for _, s := range strs {
		if s != "" {
			return s
		}
	}

	return ""
}

// ContainsFold reports whether s contains, ignoring letter case, substr.
func ContainsFold(s, substr string) (ok bool) {
	sLen, substrLen := len(s), len(substr)
	if sLen < substrLen {
		return false
	}

	if sLen == substrLen {
		return strings.EqualFold(s, substr)
	}

	first, _ := utf8.DecodeRuneInString(substr)
	firstFolded := unicode.SimpleFold(first)

	for i := 0; i != -1 && len(s) >= len(substr); {
		if strings.EqualFold(s[:substrLen], substr) {
			return true
		}

		i = strings.IndexFunc(s[1:], func(r rune) (eq bool) {
			return r == first || r == firstFolded
		})

		s = s[1+i:]
	}

	return false
}

// FilterOut returns a copy of strs with all strings for which f returned true
// removed.
func FilterOut(strs []string, f func(s string) (ok bool)) (filtered []string) {
	for _, s := range strs {
		if !f(s) {
			filtered = append(filtered, s)
		}
	}

	return filtered
}

// InSlice checks if strs contains str.
func InSlice(strs []string, str string) (ok bool) {
	for _, s := range strs {
		if s == str {
			return true
		}
	}

	return false
}

// SplitTrimmed slices str into all substrings separated by sep and returns
// a slice of the trimmed substrings between those separators with empty strings
// skipped.  If str has no such substrings, strs is an empty slice.
func SplitTrimmed(str, sep string) (strs []string) {
	str = strings.TrimSpace(str)
	if str == "" {
		return []string{}
	}

	split := strings.Split(str, sep)

	// Use the same underlying storage to reduce allocations.
	strs = split[:0]
	for _, s := range split {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		strs = append(strs, s)
	}

	// Reset the remaining elements of the original slice so that the
	// garbage is collected.
	for i := len(strs); i < len(split); i++ {
		split[i] = ""
	}

	return strs
}

// WriteToBuilder is a convenient wrapper for strings.(*Builder).WriteString
// that deals with multiple strings and ignores errors, since they are
// guaranteed to be nil.
//
// b must not be nil.
func WriteToBuilder(b *strings.Builder, strs ...string) {
	for _, s := range strs {
		_, _ = b.WriteString(s)
	}
}
