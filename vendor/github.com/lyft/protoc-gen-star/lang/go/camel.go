package pgsgo

import (
	pgs "github.com/lyft/protoc-gen-star"
)

// PGGUpperCamelCase converts Name n to the protoc-gen-go defined upper
// camelcase. The rules are slightly different from pgs.UpperCamelCase in that
// leading underscores are converted to 'X', mid-string underscores followed by
// lowercase letters are removed and the letter is capitalized, all other
// punctuation is preserved. This method should be used when deriving names of
// protoc-gen-go generated code (ie, message/service struct names and field
// names).
//
// See: https://godoc.org/github.com/golang/protobuf/protoc-gen-go/generator#CamelCase
func PGGUpperCamelCase(n pgs.Name) pgs.Name {
	return pgs.Name(camelCase(n.String()))
}

// Below copied from https://github.com/golang/protobuf/blob/d04d7b157bb510b1e0c10132224b616ac0e26b17/protoc-gen-go/generator/generator.go#L2640-L2685,
// to fix deprecation warning: https://github.com/golang/protobuf/blob/b5de78c91d0d09482d65f0a96927631cd343d7bb/protoc-gen-go/generator/generator.go#L42-L47

// CamelCase returns the CamelCased name.
// If there is an interior underscore followed by a lower case letter,
// drop the underscore and convert the letter to upper case.
// There is a remote possibility of this rewrite causing a name collision,
// but it's so remote we're prepared to pretend it's nonexistent - since the
// C++ generator lowercases names, it's extremely unlikely to have two fields
// with different capitalizations.
// In short, _my_field_name_2 becomes XMyFieldName_2.
func camelCase(s string) string {
	if s == "" {
		return ""
	}
	t := make([]byte, 0, 32)
	i := 0
	if s[0] == '_' {
		// Need a capital letter; drop the '_'.
		t = append(t, 'X')
		i++
	}
	// Invariant: if the next letter is lower case, it must be converted
	// to upper case.
	// That is, we process a word at a time, where words are marked by _ or
	// upper case letter. Digits are treated as words.
	for ; i < len(s); i++ {
		c := s[i]
		if c == '_' && i+1 < len(s) && isASCIILower(s[i+1]) {
			continue // Skip the underscore in s.
		}
		if isASCIIDigit(c) {
			t = append(t, c)
			continue
		}
		// Assume we have a letter now - if not, it's a bogus identifier.
		// The next word is a sequence of characters that must start upper case.
		if isASCIILower(c) {
			c ^= ' ' // Make it a capital letter.
		}
		t = append(t, c) // Guaranteed not lower case.
		// Accept lower case sequence that follows.
		for i+1 < len(s) && isASCIILower(s[i+1]) {
			i++
			t = append(t, s[i])
		}
	}
	return string(t)
}

// Is c an ASCII lower-case letter?
func isASCIILower(c byte) bool {
	return 'a' <= c && c <= 'z'
}

// Is c an ASCII digit?
func isASCIIDigit(c byte) bool {
	return '0' <= c && c <= '9'
}
