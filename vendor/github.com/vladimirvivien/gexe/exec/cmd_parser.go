package exec

import (
	"bufio"
	"io"
	"strings"
	"unicode"
)

// parse parses space-separated string into words including quoted words:
//
//  aaa "bbb" "ccc ddd" '"eee ff"'
//
//  NB:
//  - aaa"abcd": returns whole string.
//  - "aaa"bbb:  returns two words "aaa" and "bbb"
func parse(val string) ([]string, error) {
	rdr := bufio.NewReader(strings.NewReader(val))
	var startQuote rune
	var word strings.Builder
	words := make([]string, 0)
	inWord := false
	inQuote := false
	squashed := false

	for {
		token, _, err := rdr.ReadRune()
		if err != nil {
			if err == io.EOF {
				remainder := word.String()
				if len(remainder) > 0 {
					words = append(words, remainder)
				}
				return words, nil
			}
			return nil, err
		}

		switch {
		case isChar(token):
			if !inWord {
				inWord = true
			}
			word.WriteRune(token)

		case isQuote(token):
			if !inWord {
				inWord, inQuote = true, true
				startQuote = token
				continue
			}

			// handles case when unquoted runs into quoted: abc"defg"
			// start the quote here
			if inWord && !inQuote {
				inQuote, squashed = true, true
				startQuote = token
				word.WriteRune(token)
				continue
			}

			// handle embedded quote (i.e "'aa'")
			if inWord && inQuote && token != startQuote {
				word.WriteRune(token)
				continue
			}

			// capture closing quote when in abc"defg"
			if squashed {
				word.WriteRune(token)
			}

			inWord = false
			inQuote = false
			squashed = false
			//store
			words = append(words, word.String())
			word.Reset()

		case unicode.IsSpace(token):
			if !inWord {
				inWord = false
				continue
			}

			// capture quoted space
			if inWord && inQuote {
				word.WriteRune(token)
				continue
			}

			// end of word
			inWord = false
			words = append(words, word.String())
			word.Reset()
		}
	}
}

func isQuote(r rune) bool {
	switch r {
	case '"', '\'':
		return true
	}
	return false
}

func isChar(r rune) bool {
	return !isQuote(r) && !unicode.IsSpace(r)
}
