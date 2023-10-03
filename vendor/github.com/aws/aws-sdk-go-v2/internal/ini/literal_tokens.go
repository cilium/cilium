package ini

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

var (
	runesTrue  = []rune("true")
	runesFalse = []rune("false")
)

// isCaselessLitValue is a caseless value comparison, assumes want is already lower-cased for efficiency.
func isCaselessLitValue(want, have []rune) bool {
	if len(have) < len(want) {
		return false
	}

	for i := 0; i < len(want); i++ {
		if want[i] != unicode.ToLower(have[i]) {
			return false
		}
	}

	return true
}

func isValid(b []rune) (bool, int, error) {
	if len(b) == 0 {
		// TODO: should probably return an error
		return false, 0, nil
	}

	return isValidRune(b[0]), 1, nil
}

func isValidRune(r rune) bool {
	return r != ':' && r != '=' && r != '[' && r != ']' && r != ' ' && r != '\n'
}

// ValueType is an enum that will signify what type
// the Value is
type ValueType int

func (v ValueType) String() string {
	switch v {
	case NoneType:
		return "NONE"
	case StringType:
		return "STRING"
	}

	return ""
}

// ValueType enums
const (
	NoneType = ValueType(iota)
	StringType
	QuotedStringType
	// FUTURE(2226) MapType
)

// Value is a union container
type Value struct {
	Type ValueType
	raw  []rune

	str string
	// FUTURE(2226) mp map[string]string
}

func newValue(t ValueType, base int, raw []rune) (Value, error) {
	v := Value{
		Type: t,
		raw:  raw,
	}

	switch t {
	case StringType:
		v.str = string(raw)
	case QuotedStringType:
		v.str = string(raw[1 : len(raw)-1])
	}

	return v, nil
}

// NewStringValue returns a Value type generated using a string input.
func NewStringValue(str string) (Value, error) {
	return newValue(StringType, 10, []rune(str))
}

func (v Value) String() string {
	switch v.Type {
	case StringType:
		return fmt.Sprintf("string: %s", string(v.raw))
	case QuotedStringType:
		return fmt.Sprintf("quoted string: %s", string(v.raw))
	default:
		return "union not set"
	}
}

func newLitToken(b []rune) (Token, int, error) {
	n := 0
	var err error

	token := Token{}
	if b[0] == '"' {
		n, err = getStringValue(b)
		if err != nil {
			return token, n, err
		}

		token = newToken(TokenLit, b[:n], QuotedStringType)
	} else {
		n, err = getValue(b)
		token = newToken(TokenLit, b[:n], StringType)
	}

	return token, n, err
}

// IntValue returns an integer value
func (v Value) IntValue() (int64, bool) {
	i, err := strconv.ParseInt(string(v.raw), 0, 64)
	if err != nil {
		return 0, false
	}
	return i, true
}

// FloatValue returns a float value
func (v Value) FloatValue() (float64, bool) {
	f, err := strconv.ParseFloat(string(v.raw), 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// BoolValue returns a bool value
func (v Value) BoolValue() (bool, bool) {
	// we don't use ParseBool as it recognizes more than what we've
	// historically supported
	if isCaselessLitValue(runesTrue, v.raw) {
		return true, true
	} else if isCaselessLitValue(runesFalse, v.raw) {
		return false, true
	}
	return false, false
}

func isTrimmable(r rune) bool {
	switch r {
	case '\n', ' ':
		return true
	}
	return false
}

// StringValue returns the string value
func (v Value) StringValue() string {
	switch v.Type {
	case StringType:
		return strings.TrimFunc(string(v.raw), isTrimmable)
	case QuotedStringType:
		// preserve all characters in the quotes
		return string(removeEscapedCharacters(v.raw[1 : len(v.raw)-1]))
	default:
		return strings.TrimFunc(string(v.raw), isTrimmable)
	}
}

func contains(runes []rune, c rune) bool {
	for i := 0; i < len(runes); i++ {
		if runes[i] == c {
			return true
		}
	}

	return false
}

func runeCompare(v1 []rune, v2 []rune) bool {
	if len(v1) != len(v2) {
		return false
	}

	for i := 0; i < len(v1); i++ {
		if v1[i] != v2[i] {
			return false
		}
	}

	return true
}
