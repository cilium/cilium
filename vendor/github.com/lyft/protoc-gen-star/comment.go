package pgs

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const commentPrefix = "//"

// C returns a comment block, wrapping when the line's length will exceed wrap.
func C(wrap int, args ...interface{}) string {
	s := commentScanner(wrap, args...)
	buf := &bytes.Buffer{}

	for s.Scan() {
		fmt.Fprintln(buf, commentPrefix, s.Text())
	}

	return buf.String()
}

// C80 is an alias for C(80, args...)
func C80(args ...interface{}) string { return C(80, args...) }

func commentScanner(wrap int, args ...interface{}) *bufio.Scanner {
	s := bufio.NewScanner(strings.NewReader(fmt.Sprint(args...)))
	s.Split(splitComment(wrap - 3))
	return s
}

func splitComment(w int) bufio.SplitFunc {
	return func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		var r rune

		start := 0
		lastSpace := 0

		for width := 0; start < len(data); start += width {
			r, width = utf8.DecodeRune(data[start:])
			if !unicode.IsSpace(r) {
				break
			}
		}

		for width, i := 0, start; i < len(data); i += width {
			r, width = utf8.DecodeRune(data[i:])
			if unicode.IsSpace(r) {
				if i >= w { // we are at our max comment width
					if lastSpace == 0 { // the token cannot be broken down further, allow it to break the limit
						return i + width, data[start:i], nil
					}
					return lastSpace, data[start:lastSpace], nil
				}
				lastSpace = i
			}
		}

		if atEOF && len(data) > start {
			return len(data), bytes.TrimSpace(data[start:]), nil
		}

		return start, nil, nil
	}
}
