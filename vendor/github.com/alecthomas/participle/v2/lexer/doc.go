// Package lexer defines interfaces and implementations used by Participle to perform lexing.
//
// The primary interfaces are Definition and Lexer. There are two concrete implementations
// included. The first is one based on Go's text/scanner package. The second is Participle's
// default stateful/modal lexer.
//
// The stateful lexer is based heavily on the approach used by Chroma (and Pygments).
//
// It is a state machine defined by a map of rules keyed by state. Each rule
// is a named regex and optional operation to apply when the rule matches.
//
// As a convenience, any Rule starting with a lowercase letter will be elided from output.
//
// Lexing starts in the "Root" group. Each rule is matched in order, with the first
// successful match producing a lexeme. If the matching rule has an associated Action
// it will be executed.
//
// A state change can be introduced with the Action `Push(state)`. `Pop()` will
// return to the previous state.
//
// To reuse rules from another state, use `Include(state)`.
//
// As a special case, regexes containing backrefs in the form \N (where N is a digit)
// will match the corresponding capture group from the immediate parent group. This
// can be used to parse, among other things, heredocs.
//
// See the README, example and tests in this package for details.
package lexer
