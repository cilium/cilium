package cparser

import (
	"github.com/alecthomas/participle/v2/lexer"
)

// ASTNode is implemented by all AST nodes in this package
type ASTNode interface {
	Children() []ASTNode
	GetHead() lexer.Position
	GetTail() lexer.Position
}

// BaseNode contains basic shared features and is embedded by all nodes
type BaseNode struct {
	// Head is the position of the starting character of a node
	Head lexer.Position
	// Tail is the position of the last character of a node
	Tail lexer.Position
}

// SetSpan sets both the head and tail position
func (n *BaseNode) SetSpan(head, tail *lexer.Token) {
	n.SetHead(head)
	n.SetTail(tail)
}

// GetHead returns the position of the starting character of a node
func (n *BaseNode) GetHead() lexer.Position {
	return n.Head
}

// BaseNode sets the positions of the first character, it takes the position from the given token
func (n *BaseNode) SetHead(token *lexer.Token) {
	if token != nil {
		n.Head = token.Pos
	}
}

// GetTail returns the position of the last character of a node
func (n *BaseNode) GetTail() lexer.Position {
	return n.Tail
}

// BaseNode sets the positions of the last character, it takes the position from the given token and adds its length
func (n *BaseNode) SetTail(token *lexer.Token) {
	if token != nil {
		n.Tail = token.Pos
		n.Tail.Advance(token.Value)
	}
}

// TranslationUnit is a full file containing C code.
// ISO/IEC 9899:TC2 - 6.9 External definitions
type TranslationUnit struct {
	BaseNode

	ExternalDeclarations []*ExternalDeclaration
}

// Children returns the child nodes
func (n *TranslationUnit) Children() []ASTNode {
	var children []ASTNode
	for _, v := range n.ExternalDeclarations {
		children = append(children, v)
	}
	return children
}

// ExternalDeclaration declares a type, global variable, or function
// ISO/IEC 9899:TC2 - 6.9 External definitions
type ExternalDeclaration struct {
	BaseNode

	FuncDef *FunctionDefinition
	Decl    *Declaration
}

// Children returns the child nodes
func (n *ExternalDeclaration) Children() []ASTNode {
	var children []ASTNode
	if n.FuncDef != nil {
		children = append(children, n.FuncDef)
	}
	if n.Decl != nil {
		children = append(children, n.Decl)
	}
	return children
}

// FunctionDefinition contains the function of a function
// ISO/IEC 9899:TC2 - 6.9.1 Function definitions
type FunctionDefinition struct {
	BaseNode

	// The keywords, return value, name and paramenters of the function.
	DeclaratorAndSpec TokenList
	// The function body
	CompoundStatement *CompoundStatement
}

// Children returns the child nodes
func (n *FunctionDefinition) Children() []ASTNode {
	var children []ASTNode
	if n.CompoundStatement != nil {
		children = append(children, n.CompoundStatement)
	}
	return children
}

// CompoundStatement is a scope { } and all of the items within that scope
// ISO/IEC 9899:TC2 - 6.8.2 Compound statement
type CompoundStatement struct {
	BaseNode

	BlockItems []*BlockItem
}

// Children returns the child nodes
func (n *CompoundStatement) Children() []ASTNode {
	var children []ASTNode
	for _, v := range n.BlockItems {
		children = append(children, v)
	}
	return children
}

// BlockItem is a variable declaration or "something else" aka a statement
// ISO/IEC 9899:TC2 - 6.8.2 Compound statement
type BlockItem struct {
	BaseNode

	Declaration *Declaration
	Statement   *Statement
}

// Children returns the child nodes
func (n *BlockItem) Children() []ASTNode {
	var children []ASTNode
	if n.Declaration != nil {
		children = append(children, n.Declaration)
	}
	if n.Statement != nil {
		children = append(children, n.Statement)
	}
	return children
}

// Declaration is a variable declaration
// ISO/IEC 9899:TC2 - 6.7 Declarations
type Declaration struct {
	BaseNode
}

// Children returns the child nodes
func (n *Declaration) Children() []ASTNode {
	return nil
}

// Statement is code other than a variable declaration.
// ISO/IEC 9899:TC2 - 6.8 Statements and blocks
type Statement struct {
	BaseNode

	// A goto label, switch case or default case.
	LabeledStatement *LabeledStatement
	// A scope, { }
	CompoundStatement *CompoundStatement
	// Anything other than control flow, e.g ('abc++;' or 'def[abc] = ++somefunc();')
	ExpressionStatement *ExpressionStatement
	// A if or switch statement
	SelectionStatement *SelectionStatement
	// A loop (for, while, do-while)
	IterationStatement *IterationStatement
	// A jump (goto, continue, break)
	JumpStatement *JumpStatement
}

// Children returns the child nodes
func (n *Statement) Children() []ASTNode {
	var children []ASTNode
	if n.LabeledStatement != nil {
		children = append(children, n.LabeledStatement)
	}
	if n.CompoundStatement != nil {
		children = append(children, n.CompoundStatement)
	}
	if n.ExpressionStatement != nil {
		children = append(children, n.ExpressionStatement)
	}
	if n.SelectionStatement != nil {
		children = append(children, n.SelectionStatement)
	}
	if n.IterationStatement != nil {
		children = append(children, n.IterationStatement)
	}
	if n.JumpStatement != nil {
		children = append(children, n.JumpStatement)
	}
	return children
}

// LabeledStatement is a goto label, switch case or switch default case.
// ISO/IEC 9899:TC2 - 6.8.1 Labeled statements
type LabeledStatement struct {
	BaseNode

	// Name of the label, ("case" or "default" in switch cases)
	Label string
	// The value of a switch case, nil otherwise
	ConstantExpression TokenList
	// The statement after the label
	Statement *Statement
}

// Children returns the child nodes
func (n *LabeledStatement) Children() []ASTNode {
	var children []ASTNode
	if n.Statement != nil {
		children = append(children, n.Statement)
	}
	return children
}

// ExpressionStatement is anything other than control flow, e.g ('abc++;' or 'def[abc] = ++somefunc();')
// ISO/IEC 9899:TC2 - 6.8.3 Expression and null statements
type ExpressionStatement struct {
	BaseNode

	Tokens TokenList
}

// Children returns the child nodes
func (n *ExpressionStatement) Children() []ASTNode {
	return nil
}

// SelectionStatement is a if, if-else, or switch case
// ISO/IEC 9899:TC2 - 6.8.4 Selection statements
type SelectionStatement struct {
	BaseNode

	// Additional position information which is particularly useful for code coverage annotation.
	ClosingBracket lexer.Position
	ElseToken      *lexer.Position

	Expression TokenList
	IfBody     *Statement
	ElseBody   *Statement
	SwitchBody *Statement
}

// Children returns the child nodes
func (n *SelectionStatement) Children() []ASTNode {
	var children []ASTNode
	if n.IfBody != nil {
		children = append(children, n.IfBody)
	}
	if n.ElseBody != nil {
		children = append(children, n.ElseBody)
	}
	if n.SwitchBody != nil {
		children = append(children, n.SwitchBody)
	}
	return children
}

// IterationStatement is a while, for, or do-while loop
// ISO/IEC 9899:TC2 - 6.8.5 Iteration statements
type IterationStatement struct {
	BaseNode

	While   *WhileStatement
	For     *ForStatement
	DoWhile *DoWhileStatement
}

// Children returns the child nodes
func (n *IterationStatement) Children() []ASTNode {
	var children []ASTNode
	if n.While != nil {
		children = append(children, n.While)
	}
	if n.For != nil {
		children = append(children, n.For)
	}
	if n.DoWhile != nil {
		children = append(children, n.DoWhile)
	}
	return children
}

// WhileStatement is a while loop
// ISO/IEC 9899:TC2 - 6.8.5 Iteration statements
type WhileStatement struct {
	BaseNode

	// Closing bracket location, which is useful for coloring coverage reports.
	ClosingBracket lexer.Position

	GuardExpression TokenList
	Body            *Statement
}

// Children returns the child nodes
func (n *WhileStatement) Children() []ASTNode {
	var children []ASTNode
	if n.Body != nil {
		children = append(children, n.Body)
	}
	return children
}

// DoWhileStatement is a do-while loop
// ISO/IEC 9899:TC2 - 6.8.5 Iteration statements
type DoWhileStatement struct {
	BaseNode

	Body            *Statement
	GuardExpression TokenList
}

// Children returns the child nodes
func (n *DoWhileStatement) Children() []ASTNode {
	var children []ASTNode
	if n.Body != nil {
		children = append(children, n.Body)
	}
	return children
}

// ForStatement is a for loop
// ISO/IEC 9899:TC2 - 6.8.5 Iteration statements
type ForStatement struct {
	BaseNode

	ClosingBracket lexer.Position

	InitExpression      TokenList
	GuardExpression     TokenList
	IterationExpression TokenList
	Body                *Statement
}

// Children returns the child nodes
func (n *ForStatement) Children() []ASTNode {
	var children []ASTNode
	if n.Body != nil {
		children = append(children, n.Body)
	}
	return children
}

// JumpStatement is a continue, break, goto, or return statement.
// ISO/IEC 9899:TC2 - 6.8.6 Jump statements
type JumpStatement struct {
	BaseNode

	// "continue" or "break", empty if goto
	ContinueBreak string
	// The name of the goto label, empty if not goto
	GotoIdent string
	// The expression, the value of which is returned.
	ReturnExpression TokenList
}

// Children returns the child nodes
func (n *JumpStatement) Children() []ASTNode {
	return nil
}

// VisitDepthFirst facilitates a depth first traversal of the AST. `fn` is called for every node in the sub-tree.
// `parents` contains a slice of parents of the current node, len(parents)-1 being the direct parent and 0 being root.
func VisitDepthFirst(node ASTNode, fn func(node ASTNode, parents []ASTNode)) {
	visitDepthFirst(node, fn, nil)
}

func visitDepthFirst(node ASTNode, fn func(node ASTNode, parents []ASTNode), parents []ASTNode) {
	fn(node, parents)

	newParents := append(parents, node)

	children := node.Children()
	for _, child := range children {
		visitDepthFirst(child, fn, newParents)
	}
}
