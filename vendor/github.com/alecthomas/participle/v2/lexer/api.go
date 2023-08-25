package lexer

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

type TokenType int

const (
	// EOF represents an end of file.
	EOF TokenType = -(iota + 1)
)

// EOFToken creates a new EOF token at the given position.
func EOFToken(pos Position) Token {
	return Token{Type: EOF, Pos: pos}
}

// Definition is the main entry point for lexing.
type Definition interface {
	// Symbols returns a map of symbolic names to the corresponding pseudo-runes for those symbols.
	// This is the same approach as used by text/scanner. For example, "EOF" might have the rune
	// value of -1, "Ident" might be -2, and so on.
	Symbols() map[string]TokenType
	// Lex an io.Reader.
	Lex(filename string, r io.Reader) (Lexer, error)
}

// StringDefinition is an optional interface lexer Definition's can implement
// to offer a fast path for lexing strings.
type StringDefinition interface {
	LexString(filename string, input string) (Lexer, error)
}

// BytesDefinition is an optional interface lexer Definition's can implement
// to offer a fast path for lexing byte slices.
type BytesDefinition interface {
	LexBytes(filename string, input []byte) (Lexer, error)
}

// A Lexer returns tokens from a source.
type Lexer interface {
	// Next consumes and returns the next token.
	Next() (Token, error)
}

// SymbolsByRune returns a map of lexer symbol names keyed by rune.
func SymbolsByRune(def Definition) map[TokenType]string {
	symbols := def.Symbols()
	out := make(map[TokenType]string, len(symbols))
	for s, r := range symbols {
		out[r] = s
	}
	return out
}

// NameOfReader attempts to retrieve the filename of a reader.
func NameOfReader(r interface{}) string {
	if nr, ok := r.(interface{ Name() string }); ok {
		return nr.Name()
	}
	return ""
}

// Must takes the result of a Definition constructor call and returns the definition, but panics if
// it errors
//
// eg.
//
// 		lex = lexer.Must(lexer.Build(`Symbol = "symbol" .`))
func Must(def Definition, err error) Definition {
	if err != nil {
		panic(err)
	}
	return def
}

// ConsumeAll reads all tokens from a Lexer.
func ConsumeAll(lexer Lexer) ([]Token, error) {
	tokens := make([]Token, 0, 1024)
	for {
		token, err := lexer.Next()
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
		if token.Type == EOF {
			return tokens, nil
		}
	}
}

// Position of a token.
type Position struct {
	Filename string
	Offset   int
	Line     int
	Column   int
}

// Advance the Position based on the number of characters and newlines in "span".
func (p *Position) Advance(span string) {
	p.Offset += len(span)
	lines := strings.Count(span, "\n")
	p.Line += lines
	// Update column.
	if lines == 0 {
		p.Column += utf8.RuneCountInString(span)
	} else {
		p.Column = utf8.RuneCountInString(span[strings.LastIndex(span, "\n"):])
	}
}

func (p Position) GoString() string {
	return fmt.Sprintf("Position{Filename: %q, Offset: %d, Line: %d, Column: %d}",
		p.Filename, p.Offset, p.Line, p.Column)
}

func (p Position) String() string {
	filename := p.Filename
	if filename == "" {
		return fmt.Sprintf("%d:%d", p.Line, p.Column)
	}
	return fmt.Sprintf("%s:%d:%d", filename, p.Line, p.Column)
}

// A Token returned by a Lexer.
type Token struct {
	// Type of token. This is the value keyed by symbol as returned by Definition.Symbols().
	Type  TokenType
	Value string
	Pos   Position
}

// EOF returns true if this Token is an EOF token.
func (t Token) EOF() bool {
	return t.Type == EOF
}

func (t Token) String() string {
	if t.EOF() {
		return "<EOF>"
	}
	return t.Value
}

func (t Token) GoString() string {
	if t.Pos == (Position{}) {
		return fmt.Sprintf("Token{%d, %q}", t.Type, t.Value)
	}
	return fmt.Sprintf("Token@%s{%d, %q}", t.Pos.String(), t.Type, t.Value)
}

// MakeSymbolTable builds a lookup table for checking token ID existence.
//
// For each symbolic name in "types", the returned map will contain the corresponding token ID as a key.
func MakeSymbolTable(def Definition, types ...string) (map[TokenType]bool, error) {
	symbols := def.Symbols()
	table := make(map[TokenType]bool, len(types))
	for _, symbol := range types {
		rn, ok := symbols[symbol]
		if !ok {
			return nil, fmt.Errorf("lexer does not support symbol %q", symbol)
		}
		table[rn] = true
	}
	return table, nil
}
