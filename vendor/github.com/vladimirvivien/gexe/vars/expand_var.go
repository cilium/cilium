package vars

import (
	"bufio"
	"io"
	"os"
	"strings"
	"unicode"
)

var (
	defaultEscapeChar = '\\'
)

// runeStack is a simple stack implementation (with slice backing)
type runeStack struct {
	store []rune
	top   int
}

func newRuneStack() *runeStack {
	return &runeStack{store: []rune{}, top: -1}
}

func (r *runeStack) push(val rune) {
	r.top++
	if r.top > len(r.store)-1 {
		r.store = append(r.store, val)
	} else {
		r.store[r.top] = val
	}
}

func (r *runeStack) pop() rune {
	if r.isEmpty() {
		return 0
	}
	val := r.store[r.top]
	r.top--
	return val
}

func (r *runeStack) peek() rune {
	if r.isEmpty() {
		return 0
	}
	return r.store[r.top]
}

func (r *runeStack) isEmpty() bool {
	return (r.top < 0)
}

func (r *runeStack) depth() int {
	return r.top + 1
}

// ExpandVar searches str for $value or ${value} which is then evaluated
// using os.ExpandEnv. If variable starts with <escapeChar>$, the expansion
// sequence will be ignored. For instance if the escapeChar is '\',
// when \$value or \${value} is encountered, the variable expansion is ignored
// leaving the original values in the string as $value or ${value}.
func (v *Variables) ExpandVar(str string, expandFunc func(string) string) string {
	escapeChar := v.escapeChar
	if escapeChar == 0 {
		escapeChar = defaultEscapeChar
	}
	stack := newRuneStack()
	rdr := bufio.NewReader(strings.NewReader(str))
	var result strings.Builder
	var variable strings.Builder

	inVar := false
	//inEscape := false

	// Algorithm:
	// a) when <escapeChar> or $ is encountered: push onto stack
	// b) next, if stack.top = <escapeChar> and $ is encountered, skip slash, pop all items and $ unto result string
	// c) if in scape write all subsequent chars in result (except \ prefix) until/including space char or end of string
	// d) if inVar ($ followed by nonspace), save all subsequent char in variable until a space char or end of string
	for {
		token, _, err := rdr.ReadRune()
		if err != nil {
			// resolve outstanding vars and save dangling slashes/dollar signs at EOF
			if err == io.EOF {
				popAll(&result, stack)
				if inVar {
					result.WriteString(resolveVar(&variable, expandFunc))
				}
			}
			return result.String()
		}

		switch {
		// if token is escapeChar:
		// save on stack for later
		// continue
		case isEscapeChar(token, escapeChar):
			stack.push(token)

		// if token is '$':
		// 1) if stack.top (or prev token) is 'escapeChar', then no need for further
		//    parsing of stack content, pop all chars in stack unto result
		// 2) else save token on stack for further parsing
		case isDollarSign(token):
			if isEscapeChar(stack.peek(), escapeChar) {
				stack.pop()
				popAll(&result, stack)
				result.WriteRune(token)
				continue
			}
			stack.push(token)

		// if token '{':
		// 1) if stack.top = '$', start of ${variable} encountered (inVar=true)
		// 2) else write token unto result (no further parsing token)
		case isOpenCurly(token):
			if isDollarSign(stack.peek()) {
				inVar = true
				variable.WriteRune(stack.pop())
				popAll(&result, stack)
				variable.WriteRune(token)
				continue
			}
			result.WriteRune(token)

		// handle all other chars
		default:
			switch {
			// if token is '}':
			// 1) if inVar=true, assume varirable boundary,
			//      expand/save var in result str
			// 2) else, save token in result (no further parsing of token)
			case isCloseCurly(token):
				if inVar {
					inVar = false
					variable.WriteRune(token)
					result.WriteString(resolveVar(&variable, expandFunc))
					continue
				}
				result.WriteRune(token)

			// if token is word boundary (space, punctuations, symbols, etc):
			// 1) if inVar=true, assume variable boundary
			//      expand/save variable in result str
			// 2) else, pop all previously saved word tokens from stack unto result str
			//      write current token unto result str
			case isBoundary(token):
				if inVar {
					inVar = false
					result.WriteString(resolveVar(&variable, expandFunc))
					result.WriteRune(token)
					continue
				}
				popAll(&result, stack)
				result.WriteRune(token)

			// if token is not a boundary char (letter):
			// 1) if inVar=true, save token as part of a var name
			// 2) if stack.top (prev token) is '$', assume start of a new var
			// 3) otherwise write token unto result str
			default:
				if inVar {
					variable.WriteRune(token)
					continue
				}

				if isDollarSign(stack.peek()) {
					inVar = true
					variable.WriteRune(stack.pop())
					variable.WriteRune(token)
					continue
				}

				popAll(&result, stack)
				result.WriteRune(token)
			}
		}
	}
}

func isDollarSign(r rune) bool {
	return r == '$'
}

func isEscapeChar(r rune, escapeChar rune) bool {
	return r == escapeChar
}

func isOpenCurly(r rune) bool {
	return r == '{'
}
func isCloseCurly(r rune) bool {
	return r == '}'
}
func popAll(target *strings.Builder, stack *runeStack) {
	for !stack.isEmpty() {
		target.WriteRune(stack.pop())
	}
}

func resolveVar(variable *strings.Builder, expandFunc func(string) string) string {
	val := variable.String()
	variable.Reset()
	return os.Expand(val, expandFunc)
}

func isBoundary(token rune) bool {
	switch {
	case unicode.IsSpace(token), token == ':', token == '#', token == '%':
		return true
	}
	return false
}
