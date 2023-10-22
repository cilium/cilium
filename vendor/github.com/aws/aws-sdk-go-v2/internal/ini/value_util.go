package ini

import (
	"fmt"
)

// getStringValue will return a quoted string and the amount
// of bytes read
//
// an error will be returned if the string is not properly formatted
func getStringValue(b []rune) (int, error) {
	if b[0] != '"' {
		return 0, NewParseError("strings must start with '\"'")
	}

	endQuote := false
	i := 1

	for ; i < len(b) && !endQuote; i++ {
		if escaped := isEscaped(b[:i], b[i]); b[i] == '"' && !escaped {
			endQuote = true
			break
		} else if escaped {
			/*c, err := getEscapedByte(b[i])
			if err != nil {
				return 0, err
			}

			b[i-1] = c
			b = append(b[:i], b[i+1:]...)
			i--*/

			continue
		}
	}

	if !endQuote {
		return 0, NewParseError("missing '\"' in string value")
	}

	return i + 1, nil
}

func getValue(b []rune) (int, error) {
	i := 0

	for i < len(b) {
		if isNewline(b[i:]) {
			break
		}

		if isOp(b[i:]) {
			break
		}

		valid, n, err := isValid(b[i:])
		if err != nil {
			return 0, err
		}

		if !valid {
			break
		}

		i += n
	}

	return i, nil
}

// isEscaped will return whether or not the character is an escaped
// character.
func isEscaped(value []rune, b rune) bool {
	if len(value) == 0 {
		return false
	}

	switch b {
	case '\'': // single quote
	case '"': // quote
	case 'n': // newline
	case 't': // tab
	case '\\': // backslash
	default:
		return false
	}

	return value[len(value)-1] == '\\'
}

func getEscapedByte(b rune) (rune, error) {
	switch b {
	case '\'': // single quote
		return '\'', nil
	case '"': // quote
		return '"', nil
	case 'n': // newline
		return '\n', nil
	case 't': // table
		return '\t', nil
	case '\\': // backslash
		return '\\', nil
	default:
		return b, NewParseError(fmt.Sprintf("invalid escaped character %c", b))
	}
}

func removeEscapedCharacters(b []rune) []rune {
	for i := 0; i < len(b); i++ {
		if isEscaped(b[:i], b[i]) {
			c, err := getEscapedByte(b[i])
			if err != nil {
				return b
			}

			b[i-1] = c
			b = append(b[:i], b[i+1:]...)
			i--
		}
	}

	return b
}
