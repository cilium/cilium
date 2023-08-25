package cparser

import (
	"fmt"
	"io"
	"os"

	"github.com/alecthomas/participle/v2/lexer"
)

const (
	// TokenSingleLineComment = "SingleLineComment"
	tokenString       = "String"
	tokenOctalNumber  = "OctalNumber"
	tokenNumber       = "Number"
	tokenHexNumber    = "HexNumber"
	tokenBinaryNumber = "BinaryNumber"
	tokenIdent        = "Ident"
	tokenPunct        = "Punct"
	tokenEscapedEOL   = "EscapedEOL"
	tokenEOL          = "EOL"
	tokenWhitespace   = "Whitespace"
)

var cLexer = lexer.MustSimple([]lexer.SimpleRule{
	// {Name: TokenSingleLineComment, Pattern: `//[^\n]*`},
	{Name: tokenString, Pattern: `"(\\"|[^"])*"`},
	{Name: tokenHexNumber, Pattern: `(0x|0X)[0-9a-fA-F]+`},
	{Name: tokenBinaryNumber, Pattern: `(0b)[01]+`},
	{Name: tokenOctalNumber, Pattern: `0[0-7]+`},
	{Name: tokenNumber, Pattern: `[-+]?(\d*\.)?\d+`},
	{Name: tokenIdent, Pattern: `[a-zA-Z_]\w*`},
	{Name: tokenPunct, Pattern: `[-[!@#$%^&*()+_={}\|:;"'<,>.?\\/~]|]`},
	{Name: tokenEscapedEOL, Pattern: `\\[\n\r]+`},
	{Name: tokenEOL, Pattern: `[\n\r]+`},
	{Name: tokenWhitespace, Pattern: `[ \t]+`},
})

// ParseFile attempts to parse a C file.
func ParseFile(path string) (*TranslationUnit, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("os open: %w", err)
	}
	defer f.Close()

	p, tl, err := NewParser(path, f)
	if err != nil {
		return nil, fmt.Errorf("new parser: %w", err)
	}

	return p.ParseTU(tl)
}

// TokenList is a list of tokens, the type contains a number of methods to make it easier to consume tokens.
type TokenList []lexer.Token

func newTokenList(list []lexer.Token) TokenList {
	return TokenList(list)
}

// Next returns the next token in the list and advances the internal cursor
func (tl *TokenList) Next() *lexer.Token {
	if len(*tl) == 0 {
		return nil
	}

	token := &(*tl)[0]
	*tl = (*tl)[1:]
	return token
}

// Peek the next token without advancing the internal cursor
func (tl *TokenList) Peek() *lexer.Token {
	return tl.PeekN(0)
}

// Peek a token `n` positions forward without advancing the internal cursor
func (tl *TokenList) PeekN(n int) *lexer.Token {
	if len(*tl) <= n {
		return nil
	}
	if n < 0 {
		return nil
	}

	return &(*tl)[n]
}

// Peek the last token contained in the list
func (tl *TokenList) PeekTail() *lexer.Token {
	return tl.PeekN(len(*tl) - 1)
}

// PeekSearch peeks ahead and searches all remaining tokens. If `fn` return true, we stop and return the matching index.
func (tl *TokenList) PeekSearch(fn func(i int, t *lexer.Token) bool) int {
	for i := range *tl {
		if fn(i, &(*tl)[i]) {
			return i
		}
	}

	return -1
}

// PeekReverseSearch peeks backward and searches all remaining tokens.
// If `fn` return true, we stop and return the matching index.
func (tl *TokenList) PeekReverseSearch(fn func(i int, t *lexer.Token) bool) int {
	for i := len(*tl) - 1; i >= 0; i-- {
		if fn(i, &((*tl)[i])) {
			return i
		}
	}

	return -1
}

// Sub returns a new token list starting from the internal cursor
func (tl *TokenList) Sub() TokenList {
	return newTokenList(*tl)
}

// SubN returns a new token list starting from the internal cursor and ending at `n`
func (tl *TokenList) SubN(n int) TokenList {
	if len(*tl) == 0 {
		return newTokenList(*tl)
	}
	if n >= len(*tl) {
		n = len(*tl) - 1
	}
	if n < 0 {
		n = 0
	}
	return newTokenList((*tl)[:n+1])
}

func (tl *TokenList) Advance(n int) {
	if n >= len(*tl) {
		*tl = nil
		return
	}

	if n < 0 {
		return
	}

	*tl = (*tl)[n:]
}

// Parser is a C file parser
type Parser struct {
	// All token in the current file
	syms map[string]lexer.TokenType
}

func newBadToken(token lexer.Token, expected string) error {
	return &UnexpectedTokenError{
		UnexpectedToken: token,
		Expected:        expected,
	}
}

// UnexpectedTokenError also known as a syntax error
type UnexpectedTokenError struct {
	UnexpectedToken lexer.Token
	Expected        string
}

func (ute *UnexpectedTokenError) Error() string {
	return fmt.Sprintf(
		"Unexpected token '%s' at %s, expected %s",
		ute.UnexpectedToken.Value,
		ute.UnexpectedToken.Pos,
		ute.Expected,
	)
}

// NewParser creates a new parser for the given filename and contents.
func NewParser(filename string, r io.Reader) (*Parser, TokenList, error) {
	lex, err := cLexer.Lex(filename, r)
	if err != nil {
		return nil, nil, fmt.Errorf("lex: %w", err)
	}

	syms := cLexer.Symbols()
	ignoredTokenTypes := []lexer.TokenType{
		syms["SingleLineComment"],
		syms["Whitespace"],
	}

	tokens := make(TokenList, 0)
tokenloop:
	for {
		token, err := lex.Next()
		if err != nil {
			return nil, nil, fmt.Errorf("lex next: %w", err)
		}

		// Ignore some token types
		for _, it := range ignoredTokenTypes {
			if token.Type == it {
				continue tokenloop
			}
		}

		tokens = append(tokens, token)

		if token.EOF() {
			break
		}
	}

	parser := &Parser{
		syms: syms,
	}

	tokens = parser.filterCode(tokens)

	return &Parser{
		syms: syms,
	}, tokens, nil
}

func (p *Parser) filterCode(tokens TokenList) TokenList {
	var (
		result TokenList
		// Was the last token a new line?
		lastNewLine = true

		inSingleLineComment bool
		inMultiLineComment  bool
	)

	for {
		cur := tokens.Next()
		if cur == nil {
			break
		}

		if inSingleLineComment {
			if cur.Type == p.EOL() {
				inSingleLineComment = false
				lastNewLine = true
			}

			// Don't include the comment token
			continue
		}

		if inMultiLineComment {
			// Look for '*/', the end of a multiline comment
			if cur.Value == "*" {
				next := tokens.Peek()
				if next != nil && next.Value == "/" {
					inMultiLineComment = false
					// Consume the peeked token if it was a '/'
					tokens.Next()
				}
			}

			// Don't include the comment token
			continue
		}

		if cur.Value == "/" {
			next := tokens.Peek()
			// handle the '//' comment case
			if next != nil && next.Value == "/" {
				inSingleLineComment = true
				tokens.Next()
				continue
			}

			// handle the '/*' comment case
			if next != nil && next.Value == "*" {
				inMultiLineComment = true
				tokens.Next()
				continue
			}
		}

		// If '#' at the start of a line, its a pre-processor statement(will treat it as a single line comment)
		if cur.Value == "#" && lastNewLine {
			inSingleLineComment = true
			continue
		}

		lastNewLine = cur.Type == p.EOL()
		if lastNewLine {
			continue
		}

		result = append(result, *cur)
	}

	return result
}

// ParseTU attempts to parse all tokens within the parser as a translation unit
func (p *Parser) ParseTU(tokens TokenList) (*TranslationUnit, error) {
	// 	(6.9) translation-unit:
	// 				external-declaration
	// 				translation-unit external-declaration
	var tu TranslationUnit

	tu.Head = tokens[0].Pos
	tu.Tail = tokens[len(tokens)-1].Pos

	for {
		// Search for the end of a expression or the closing bracket of a function in the global scope
		scopeDepth := 0
		globalScopeIsFunc := false
		off := tokens.PeekSearch(func(i int, t *lexer.Token) bool {
			if t.Type != p.Punct() {
				return false
			}

			if scopeDepth == 0 {
				next := tokens.PeekN(i + 1)
				if t.Value == ")" && next != nil && next.Value == "{" {
					globalScopeIsFunc = true
				}
			}

			if t.Value == "{" {
				scopeDepth++
			}

			if t.Value == ";" && scopeDepth == 0 {
				return true
			}

			if t.Value == "}" {
				scopeDepth--
				if scopeDepth == 0 && globalScopeIsFunc {
					return true
				}
			}

			return false
		})

		var sub TokenList
		if off == -1 {
			sub = tokens.Sub()
		} else {
			sub = tokens.SubN(off)
			tokens.Advance(off + 1)
		}

		extDect, err := p.parseExternalDeclaration(sub)
		if err != nil {
			return nil, fmt.Errorf("parse external deceleration: %w", err)
		}
		if extDect != nil {
			tu.ExternalDeclarations = append(tu.ExternalDeclarations, extDect)
		}

		if off == -1 {
			break
		}

		if tokens.Peek() == nil || tokens.Peek().EOF() {
			break
		}
	}

	return &tu, nil
}

func (p *Parser) parseExternalDeclaration(tokens TokenList) (*ExternalDeclaration, error) {
	// (6.9) external-declaration:
	// 			function-definition
	// 			declaration
	last := tokens.PeekTail()
	if last == nil {
		return nil, fmt.Errorf("no last token")
	}

	// Discard trailing tokens.
	if last.EOF() {
		return nil, nil
	}

	var extDecl ExternalDeclaration

	switch last.Value {
	case ";":
		decl, err := p.parseDeclaration(tokens)
		if err != nil {
			return nil, fmt.Errorf("parse declaration: %w", err)
		}

		extDecl.Head = decl.Head
		extDecl.Tail = decl.Tail
		extDecl.Decl = decl
	case "}":
		funcDef, err := p.parseFunctionDefinition(tokens)
		if err != nil {
			return nil, fmt.Errorf("parse function definition: %w", err)
		}

		extDecl.Head = funcDef.Head
		extDecl.Tail = funcDef.Tail
		extDecl.FuncDef = funcDef
	default:
		return nil, newBadToken(*last, "';' or '}'")
	}

	return &extDecl, nil
}

func (p *Parser) parseDeclaration(tokens TokenList) (*Declaration, error) {
	// (6.7) declaration:
	// 			declaration-specifiers init-declarator-list[opt] ;

	// Don't continue parsing declarations, a more detailed break down isn't required for code coverage
	// since we are mostly interested in expressions.

	var decl Declaration
	decl.SetSpan(tokens.Next(), tokens.PeekTail())
	return &decl, nil
}

func (p *Parser) parseFunctionDefinition(tokens TokenList) (*FunctionDefinition, error) {
	// (6.9.1) function-definition:
	// 			declaration-specifiers declarator declaration-list[opt] compound-statement

	compoundStatementStart := tokens.PeekSearch(func(i int, t *lexer.Token) bool {
		return t.Value == "{"
	})
	if compoundStatementStart == -1 {
		return nil, fmt.Errorf("can't find start of compound statement")
	}

	var funcDef FunctionDefinition
	funcDef.SetHead(tokens.Peek())

	funcDef.DeclaratorAndSpec = tokens.SubN(compoundStatementStart - 1)
	tokens.Advance(compoundStatementStart)

	var err error
	funcDef.CompoundStatement, err = p.parseCompoundStatement(tokens)
	if err != nil {
		return nil, fmt.Errorf("parse compound statement: %w", err)
	}
	funcDef.Tail = funcDef.CompoundStatement.Tail

	return &funcDef, nil
}

func (p *Parser) parseCompoundStatement(tokens TokenList) (*CompoundStatement, error) {
	// (6.8.2) compound-statement:
	// 			{ block-item-list[opt] }

	open := tokens.Next()
	if open == nil {
		return nil, fmt.Errorf("out of tokens")
	}

	if open.Value != "{" {
		return nil, newBadToken(*open, "'{'")
	}

	if tokens.PeekTail() == nil {
		return nil, fmt.Errorf("out of tokens")
	}

	tail := tokens.PeekTail()
	if tail.Value != "}" {
		return nil, newBadToken(*tail, "'}'")
	}

	tokens = tokens.SubN(len(tokens) - 2)

	var compStmt CompoundStatement

	compStmt.SetSpan(open, tail)

	for {
		var (
			block *BlockItem
			err   error
		)
		block, tokens, err = p.parseBlockItem(tokens)
		if err != nil {
			return nil, fmt.Errorf("parse block item: %w", err)
		}

		compStmt.BlockItems = append(compStmt.BlockItems, block)

		if len(tokens) == 0 {
			break
		}
	}

	return &compStmt, nil
}

func (p *Parser) parseBlockItem(tokens TokenList) (*BlockItem, TokenList, error) {
	// (6.8.2) block-item:
	// 		declaration
	// 		statement

	// Statement or Declaration
	// TODO find out which, for now everything is an Statement

	var (
		block BlockItem
		err   error
	)

	block.Statement, tokens, err = p.parseStatement(tokens)
	if err != nil {
		return nil, tokens, fmt.Errorf("parse statement: %w", err)
	}

	block.Head = block.Statement.Head
	block.Tail = block.Statement.Tail

	return &block, tokens, nil
}

func (p *Parser) parseStatement(tokens TokenList) (*Statement, TokenList, error) {
	first := tokens.Peek()
	next := tokens.PeekN(1)
	if first == nil {
		return nil, nil, fmt.Errorf("out of tokens")
	}

	var (
		stmt Statement
		err  error
	)

	// (6.8.1) labeled-statement:
	// 		identifier : statement
	// 		case constant-expression : statement
	//		default : statement
	if first.Type == p.Ident() && (next != nil && next.Value == ":") || first.Value == "case" {
		stmt.LabeledStatement, tokens, err = p.parseLabeledStatement(tokens)
		if err != nil {
			return nil, nil, fmt.Errorf("parse labeled statement: %w", err)
		}
		stmt.Head = stmt.LabeledStatement.Head
		stmt.Tail = stmt.LabeledStatement.Tail
		return &stmt, tokens, nil
	}

	// (6.8.2) compound-statement:
	// 			{ block-item-list[opt] }
	if first.Value == "{" {
		depth := 0
		closingIdx := tokens.PeekSearch(func(i int, t *lexer.Token) bool {
			if t.Value == "{" {
				depth++
			}
			if t.Value == "}" {
				depth--
				if depth == 0 {
					return true
				}
			}
			return false
		})
		if closingIdx == -1 {
			return nil, nil, fmt.Errorf("can't find closing bracket for '%s' at %s", first.Value, first.Pos)
		}

		stmt.CompoundStatement, err = p.parseCompoundStatement(tokens.SubN(closingIdx))
		if err != nil {
			return nil, nil, fmt.Errorf("parse compound statement: %w", err)
		}
		tokens.Advance(closingIdx + 1)
		stmt.Head = stmt.CompoundStatement.Head
		stmt.Tail = stmt.CompoundStatement.Tail
		return &stmt, tokens, nil
	}

	// (6.8.4) selection-statement:
	// 		if ( expression ) statement
	// 		if ( expression ) statement else statement
	// 		switch ( expression ) statement
	if first.Value == "if" || first.Value == "switch" {
		stmt.SelectionStatement, tokens, err = p.parseSelectionStatement(tokens)
		if err != nil {
			return nil, nil, fmt.Errorf("parse selection statement: %w", err)
		}
		stmt.Head = stmt.SelectionStatement.Head
		stmt.Tail = stmt.SelectionStatement.Tail
		return &stmt, tokens, nil
	}

	// (6.8.5) iteration-statement:
	// 		while ( expression ) statement
	// 		do statement while ( expression ) ;
	// 		for ( expressionopt ; expressionopt ; expressionopt ) statement
	// 		for ( declaration expressionopt ; expressionopt ) statement
	if first.Value == "while" || first.Value == "do" || first.Value == "for" {
		stmt.IterationStatement, tokens, err = p.parseIterationStatement(tokens)
		if err != nil {
			return nil, nil, fmt.Errorf("parse iteration statement: %w", err)
		}
		stmt.Head = stmt.IterationStatement.Head
		stmt.Tail = stmt.IterationStatement.Tail
		return &stmt, tokens, nil
	}

	// (6.8.6) jump-statement:
	// 		goto identifier ;
	// 		continue ;
	// 		break ;
	// 		return expressionopt ;
	if first.Value == "goto" || first.Value == "continue" || first.Value == "break" || first.Value == "return" {
		stmt.JumpStatement, tokens, err = p.parseJumpStatement(tokens)
		if err != nil {
			return nil, nil, fmt.Errorf("parse iteration statement: %w", err)
		}
		stmt.Head = stmt.JumpStatement.Head
		stmt.Tail = stmt.JumpStatement.Tail
		return &stmt, tokens, nil
	}

	// expression-statement:
	// 			expression[opt] ;

	depth := 0
	semicolonIdx := tokens.PeekSearch(func(i int, t *lexer.Token) bool {
		if t.Value == "{" {
			depth++
		}
		if t.Value == "}" {
			depth--
		}

		return depth == 0 && t.Value == ";"
	})

	stmt.ExpressionStatement = &ExpressionStatement{}
	if semicolonIdx == -1 {
		stmt.ExpressionStatement.Tokens = tokens.Sub()
		tokens = nil
	} else {
		stmt.ExpressionStatement.Tokens = tokens.SubN(semicolonIdx)
		tokens.Advance(semicolonIdx + 1)
	}
	head := stmt.ExpressionStatement.Tokens.Peek()
	tail := stmt.ExpressionStatement.Tokens.PeekTail()
	stmt.ExpressionStatement.SetSpan(head, tail)
	stmt.SetSpan(head, tail)
	return &stmt, tokens, nil
}

func (p *Parser) parseLabeledStatement(tokens TokenList) (*LabeledStatement, TokenList, error) {
	// (6.8.1) labeled-statement:
	// 		identifier : statement
	// 		case constant-expression : statement
	//		default : statement

	first := tokens.Next()
	if first == nil {
		return nil, nil, fmt.Errorf("out of tokens")
	}

	var labelStmt LabeledStatement

	labelStmt.SetHead(first)

	if first.Value == "case" {
		colonIdx := tokens.PeekSearch(func(i int, t *lexer.Token) bool {
			return t.Value == ":"
		})
		if colonIdx == -1 {
			return nil, nil, fmt.Errorf("can't find case colon")
		}

		labelStmt.Label = "case"
		labelStmt.ConstantExpression = tokens.SubN(colonIdx - 1)
		tokens.Advance(colonIdx + 1)
	} else {
		second := tokens.Next()
		if second == nil {
			return nil, nil, fmt.Errorf("out of tokens")
		}

		if first.Type != p.Ident() {
			return nil, nil, newBadToken(*first, "<ident>")
		}

		if second.Value != ":" {
			return nil, nil, newBadToken(*first, "':'")
		}

		labelStmt.Label = first.Value
	}

	subStmt, tail, err := p.parseStatement(tokens)
	if err != nil {
		return nil, nil, fmt.Errorf("parse statement: %w", err)
	}

	labelStmt.Statement = subStmt
	labelStmt.Tail = subStmt.Tail

	return &labelStmt, tail, nil
}

func (p *Parser) parseSelectionStatement(tokens TokenList) (*SelectionStatement, TokenList, error) {
	// (6.8.4) selection-statement:
	// 		if ( expression ) statement
	// 		if ( expression ) statement else statement
	// 		switch ( expression ) statement
	first := tokens.Next()
	second := tokens.Peek()

	if first == nil || second == nil {
		return nil, nil, fmt.Errorf("out of tokens")
	}

	if first.Value != "if" && first.Value != "switch" {
		return nil, tokens, newBadToken(*first, "'if' or 'switch'")
	}

	if second.Value != "(" {
		return nil, tokens, newBadToken(*second, "'('")
	}

	// Search for the closing brace matching the opening one
	depth := 0
	closingIdx := tokens.PeekSearch(func(i int, t *lexer.Token) bool {
		if t.Value == "(" {
			depth++
		}
		if t.Value == ")" {
			depth--
			if depth == 0 {
				return true
			}
		}
		return false
	})
	if closingIdx == -1 {
		return nil, tokens, fmt.Errorf("unable to find closing bracket for expression")
	}

	var selStmt SelectionStatement

	selStmt.SetHead(first)
	selStmt.ClosingBracket = tokens.PeekN(closingIdx + 1).Pos
	selStmt.Expression = tokens.SubN(closingIdx)
	tokens.Advance(closingIdx + 1)

	subStmt, tail, err := p.parseStatement(tokens)
	if err != nil {
		return nil, tokens, fmt.Errorf("parse statement: %w", err)
	}
	selStmt.Tail = subStmt.Tail

	if first.Value == "switch" {
		selStmt.SwitchBody = subStmt
		return &selStmt, tail, nil
	}

	selStmt.IfBody = subStmt

	if tail.Peek() == nil || tail.Peek().Value != "else" {
		return &selStmt, tail, nil
	}
	selStmt.ElseToken = &tail.Peek().Pos
	tail.Advance(1)

	subStmt, tail, err = p.parseStatement(tail)
	if err != nil {
		return nil, tokens, fmt.Errorf("parse statement: %w", err)
	}

	selStmt.ElseBody = subStmt
	selStmt.Tail = subStmt.Tail

	return &selStmt, tail, nil
}

func (p *Parser) parseIterationStatement(tokens TokenList) (*IterationStatement, TokenList, error) {
	// (6.8.5) iteration-statement:
	// 		while ( expression ) statement
	// 		do statement while ( expression ) ;
	// 		for ( expressionopt ; expressionopt ; expressionopt ) statement
	// 		for ( declaration expressionopt ; expressionopt ) statement

	first := tokens.Peek()
	if first == nil {
		return nil, nil, fmt.Errorf("out of tokens")
	}

	var iterStmt IterationStatement

	switch first.Value {
	case "while":
		whileExpr, tail, err := p.parseWhileExpression(tokens)
		if err != nil {
			return nil, nil, fmt.Errorf("parse while expr: %w", err)
		}
		iterStmt.While = whileExpr
		iterStmt.Head = whileExpr.Head
		iterStmt.Tail = whileExpr.Tail
		return &iterStmt, tail, nil

	case "for":
		forExpr, tail, err := p.parseForExpression(tokens)
		if err != nil {
			return nil, nil, fmt.Errorf("parse while expr: %w", err)
		}
		iterStmt.For = forExpr
		iterStmt.Head = forExpr.Head
		iterStmt.Tail = forExpr.Tail
		return &iterStmt, tail, nil

	case "do":
		doWhileExpr, tail, err := p.parseDoWhileExpression(tokens)
		if err != nil {
			return nil, nil, fmt.Errorf("parse while expr: %w", err)
		}
		iterStmt.DoWhile = doWhileExpr
		iterStmt.Head = doWhileExpr.Head
		iterStmt.Tail = doWhileExpr.Tail
		return &iterStmt, tail, nil
	}

	return nil, nil, newBadToken(*first, "'while', 'for', or 'do'")
}

func (p *Parser) parseWhileExpression(tokens TokenList) (*WhileStatement, TokenList, error) {
	// while ( expression ) statement
	first := tokens.Next()
	second := tokens.Peek()
	if first == nil || second == nil {
		return nil, nil, fmt.Errorf("out of tokens")
	}

	if first.Value != "while" {
		return nil, nil, newBadToken(*first, "'while'")
	}

	if second.Value != "(" {
		return nil, nil, newBadToken(*first, "'('")
	}

	var whileExpr WhileStatement
	whileExpr.SetHead(first)

	// Search for the closing brace matching the opening one
	depth := 0
	closingIdx := tokens.PeekSearch(func(i int, t *lexer.Token) bool {
		if t.Value == "(" {
			depth++
		}
		if t.Value == ")" {
			depth--
			if depth == 0 {
				return true
			}
		}
		return false
	})
	if closingIdx == -1 {
		return nil, tokens, fmt.Errorf("unable to find closing bracket for expression")
	}

	whileExpr.GuardExpression = tokens.SubN(closingIdx)
	whileExpr.ClosingBracket = tokens.PeekN(closingIdx + 1).Pos
	tokens.Advance(closingIdx + 1)

	bodyStmt, tail, err := p.parseStatement(tokens)
	if err != nil {
		return nil, nil, fmt.Errorf("parse statement: %w", err)
	}
	whileExpr.Body = bodyStmt
	whileExpr.Tail = bodyStmt.Tail

	return &whileExpr, tail, nil
}

func (p *Parser) parseForExpression(tokens TokenList) (*ForStatement, TokenList, error) {
	// 	for ( expressionopt ; expressionopt ; expressionopt ) statement
	// 	for ( declaration expressionopt ; expressionopt ) statement

	first := tokens.Next()
	second := tokens.Peek()
	if first == nil || second == nil {
		return nil, nil, fmt.Errorf("out of tokens")
	}

	if first.Value != "for" {
		return nil, nil, newBadToken(*first, "'for'")
	}

	if second.Value != "(" {
		return nil, nil, newBadToken(*first, "'('")
	}

	var forStmt ForStatement
	forStmt.SetHead(first)

	// Search for the closing brace matching the opening one
	depth := 0
	closingIdx := tokens.PeekSearch(func(i int, t *lexer.Token) bool {
		if t.Value == "(" {
			depth++
		}
		if t.Value == ")" {
			depth--
			if depth == 0 {
				return true
			}
		}
		return false
	})
	if closingIdx == -1 {
		return nil, tokens, fmt.Errorf("unable to find closing bracket for expression")
	}

	forStmt.ClosingBracket = tokens.PeekN(closingIdx + 1).Pos

	tokens.Advance(1)
	header := tokens.SubN(closingIdx - 2)
	tokens.Advance(closingIdx + 1)

	semiIdx := header.PeekSearch(func(i int, t *lexer.Token) bool {
		return t.Value == ";"
	})
	if semiIdx == -1 {
		return nil, nil, fmt.Errorf("missing first ';'")
	}

	forStmt.InitExpression = header.SubN(semiIdx - 1)
	header.Advance(semiIdx + 1)

	semiIdx = header.PeekSearch(func(i int, t *lexer.Token) bool {
		return t.Value == ";"
	})
	if semiIdx == -1 {
		forStmt.GuardExpression = header.Sub()
	} else {
		forStmt.GuardExpression = header.SubN(semiIdx - 1)
		header.Advance(semiIdx + 1)
		forStmt.IterationExpression = header.Sub()
	}

	body, tail, err := p.parseStatement(tokens)
	if err != nil {
		return nil, nil, fmt.Errorf("parse statement: %w", err)
	}
	forStmt.Body = body
	forStmt.Tail = body.Tail

	return &forStmt, tail, nil
}

func (p *Parser) parseDoWhileExpression(tokens TokenList) (*DoWhileStatement, TokenList, error) {
	// do statement while ( expression ) ;

	first := tokens.Next()
	if first == nil {
		return nil, nil, fmt.Errorf("out of tokens")
	}

	if first.Value != "do" {
		return nil, nil, newBadToken(*first, "'do'")
	}

	var doWhileStmt DoWhileStatement

	doWhileStmt.SetHead(first)

	body, tokens, err := p.parseStatement(tokens)
	if err != nil {
		return nil, nil, fmt.Errorf("parse statement: %w", err)
	}
	doWhileStmt.Body = body

	whileToken := tokens.Next()
	if whileToken == nil {
		return nil, nil, fmt.Errorf("out of tokens")
	}

	if whileToken.Value != "while" {
		return nil, nil, newBadToken(*whileToken, "'while'")
	}

	open := tokens.Peek()
	if open == nil {
		return nil, nil, fmt.Errorf("out of tokens")
	}

	if open.Value != "(" {
		return nil, nil, newBadToken(*whileToken, "'('")
	}

	// Search for the closing brace matching the opening one
	depth := 0
	closingIdx := tokens.PeekSearch(func(i int, t *lexer.Token) bool {
		if t.Value == "(" {
			depth++
		}
		if t.Value == ")" {
			depth--
			if depth == 0 {
				return true
			}
		}
		return false
	})
	if closingIdx == -1 {
		return nil, tokens, fmt.Errorf("unable to find closing bracket for expression")
	}

	tokens.Advance(1)
	doWhileStmt.GuardExpression = tokens.SubN(closingIdx - 2)
	tokens.Advance(closingIdx)

	last := tokens.Next()
	if last == nil {
		return nil, nil, fmt.Errorf("out of tokens")
	}

	if last.Value != ";" {
		return nil, nil, newBadToken(*last, "';'")
	}
	doWhileStmt.SetTail(last)

	return &doWhileStmt, tokens, nil
}

func (p *Parser) parseJumpStatement(tokens TokenList) (*JumpStatement, TokenList, error) {
	// (6.8.6) jump-statement:
	// 		goto identifier ;
	// 		continue ;
	// 		break ;
	// 		return expressionopt ;

	first := tokens.Next()
	if first == nil {
		return nil, nil, fmt.Errorf("out of tokens")
	}

	var jmpStmt JumpStatement

	jmpStmt.SetHead(first)

	switch first.Value {
	case "goto":
		second := tokens.Next()
		if second == nil {
			return nil, nil, fmt.Errorf("out of tokens")
		}

		jmpStmt.GotoIdent = second.Value

	case "continue", "break":
		jmpStmt.ContinueBreak = first.Value

	case "return":
		semiIdx := tokens.PeekSearch(func(i int, t *lexer.Token) bool {
			return t.Value == ";"
		})
		if semiIdx == -1 {
			return nil, nil, fmt.Errorf("can't find semicolon")
		}

		jmpStmt.ReturnExpression = tokens.SubN(semiIdx - 1)
		tokens.Advance(semiIdx)
	default:
		return nil, nil, newBadToken(*first, "'goto', 'continue', 'break', or 'return'")
	}

	last := tokens.Next()
	if last == nil {
		return nil, nil, fmt.Errorf("out of tokens")
	}

	if last.Value != ";" {
		return nil, nil, newBadToken(*last, "';'")
	}
	jmpStmt.SetTail(last)

	return &jmpStmt, tokens, nil
}

// Ident returns the lexer token type for a identifier
func (p *Parser) Ident() lexer.TokenType {
	return p.syms[tokenIdent]
}

// Punct returns the lexer token type for a punctuation
func (p *Parser) Punct() lexer.TokenType {
	return p.syms[tokenPunct]
}

// EOL returns the lexer token type for a end of line token
func (p *Parser) EOL() lexer.TokenType {
	return p.syms[tokenEOL]
}
