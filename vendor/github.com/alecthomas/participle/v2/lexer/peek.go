package lexer

// PeekingLexer supports arbitrary lookahead as well as cloning.
type PeekingLexer struct {
	Checkpoint
	tokens []Token
	elide  map[TokenType]bool
}

// RawCursor index in the token stream.
type RawCursor int

// Checkpoint wraps the mutable state of the PeekingLexer.
//
// Copying and restoring just this state is a bit faster than copying the entire PeekingLexer.
type Checkpoint struct {
	rawCursor  RawCursor // The raw position of the next possibly elided token
	nextCursor RawCursor // The raw position of the next non-elided token
	cursor     int       // Index of the next non-elided token among other non-elided tokens
}

// Upgrade a Lexer to a PeekingLexer with arbitrary lookahead.
//
// "elide" is a slice of token types to elide from processing.
func Upgrade(lex Lexer, elide ...TokenType) (*PeekingLexer, error) {
	r := &PeekingLexer{
		elide: make(map[TokenType]bool, len(elide)),
	}
	for _, rn := range elide {
		r.elide[rn] = true
	}
	for {
		t, err := lex.Next()
		if err != nil {
			return r, err
		}
		r.tokens = append(r.tokens, t)
		if t.EOF() {
			break
		}
	}
	r.advanceToNonElided()
	return r, nil
}

// Range returns the slice of tokens between the two cursor points.
func (p *PeekingLexer) Range(rawStart, rawEnd RawCursor) []Token {
	return p.tokens[rawStart:rawEnd]
}

// Cursor position in tokens, excluding elided tokens.
func (c Checkpoint) Cursor() int {
	return c.cursor
}

// RawCursor position in tokens, including elided tokens.
func (c Checkpoint) RawCursor() RawCursor {
	return c.rawCursor
}

// Next consumes and returns the next token.
func (p *PeekingLexer) Next() *Token {
	t := &p.tokens[p.nextCursor]
	if t.EOF() {
		return t
	}
	p.nextCursor++
	p.rawCursor = p.nextCursor
	p.cursor++
	p.advanceToNonElided()
	return t
}

// Peek ahead at the next non-elided token.
func (p *PeekingLexer) Peek() *Token {
	return &p.tokens[p.nextCursor]
}

// RawPeek peeks ahead at the next raw token.
//
// Unlike Peek, this will include elided tokens.
func (p *PeekingLexer) RawPeek() *Token {
	return &p.tokens[p.rawCursor]
}

// advanceToNonElided advances nextCursor to the closest non-elided token
func (p *PeekingLexer) advanceToNonElided() {
	for ; ; p.nextCursor++ {
		t := &p.tokens[p.nextCursor]
		if t.EOF() || !p.elide[t.Type] {
			return
		}
	}
}

// PeekAny peeks forward over elided and non-elided tokens.
//
// Elided tokens will be returned if they match, otherwise the next
// non-elided token will be returned.
//
// The returned RawCursor position is the location of the returned token.
// Use FastForward to move the internal cursors forward.
func (p *PeekingLexer) PeekAny(match func(Token) bool) (t Token, rawCursor RawCursor) {
	for i := p.rawCursor; ; i++ {
		t = p.tokens[i]
		if t.EOF() || match(t) || !p.elide[t.Type] {
			return t, i
		}
	}
}

// FastForward the internal cursors to this RawCursor position.
func (p *PeekingLexer) FastForward(rawCursor RawCursor) {
	for ; p.rawCursor <= rawCursor; p.rawCursor++ {
		t := &p.tokens[p.rawCursor]
		if t.EOF() {
			break
		}
		if !p.elide[t.Type] {
			p.cursor++
		}
	}
	p.nextCursor = p.rawCursor
	p.advanceToNonElided()
}

func (p *PeekingLexer) MakeCheckpoint() Checkpoint {
	return p.Checkpoint
}

func (p *PeekingLexer) LoadCheckpoint(checkpoint Checkpoint) {
	p.Checkpoint = checkpoint
}
