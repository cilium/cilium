package lexer

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

var (
	backrefReplace = regexp.MustCompile(`(\\+)(\d)`)
)

// Option for modifying how the Lexer works.
type Option func(d *StatefulDefinition)

// A Rule matching input and possibly changing state.
type Rule struct {
	Name    string
	Pattern string
	Action  Action
}

// Rules grouped by name.
type Rules map[string][]Rule

// compiledRule is a Rule with its pattern compiled.
type compiledRule struct {
	Rule
	ignore bool
	RE     *regexp.Regexp
}

// compiledRules grouped by name.
type compiledRules map[string][]compiledRule

// A Action is applied when a rule matches.
type Action interface {
	// Actions are responsible for validating the match. ie. if they consumed any input.
	applyAction(lexer *StatefulLexer, groups []string) error
}

// RulesAction is an optional interface that Actions can implement.
//
// It is applied during rule construction to mutate the rule map.
type RulesAction interface {
	applyRules(state string, rule int, rules compiledRules) error
}

// InitialState overrides the default initial state of "Root".
func InitialState(state string) Option {
	return func(d *StatefulDefinition) {
		d.initialState = state
	}
}

// MatchLongest causes the Lexer to continue checking rules past the first match.
// If any subsequent rule has a longer match, it will be used instead.
func MatchLongest() Option {
	return func(d *StatefulDefinition) {
		d.matchLongest = true
	}
}

// ActionPop pops to the previous state when the Rule matches.
type ActionPop struct{}

func (p ActionPop) applyAction(lexer *StatefulLexer, groups []string) error {
	if groups[0] == "" {
		return errors.New("did not consume any input")
	}
	lexer.stack = lexer.stack[:len(lexer.stack)-1]
	return nil
}

// Pop to the previous state.
func Pop() Action {
	return ActionPop{}
}

// ReturnRule signals the lexer to return immediately.
var ReturnRule = Rule{"returnToParent", "", nil}

// Return to the parent state.
//
// Useful as the last rule in a sub-state.
func Return() Rule { return ReturnRule }

// ActionPush pushes the current state and switches to "State" when the Rule matches.
type ActionPush struct{ State string }

func (p ActionPush) applyAction(lexer *StatefulLexer, groups []string) error {
	if groups[0] == "" {
		return errors.New("did not consume any input")
	}
	lexer.stack = append(lexer.stack, lexerState{name: p.State, groups: groups})
	return nil
}

// Push to the given state.
//
// The target state will then be the set of rules used for matching
// until another Push or Pop is encountered.
func Push(state string) Action {
	return ActionPush{state}
}

type include struct{ state string }

func (i include) applyAction(lexer *StatefulLexer, groups []string) error {
	panic("should not be called")
}

func (i include) applyRules(state string, rule int, rules compiledRules) error {
	includedRules, ok := rules[i.state]
	if !ok {
		return fmt.Errorf("invalid include state %q", i.state)
	}
	clone := make([]compiledRule, len(includedRules))
	copy(clone, includedRules)
	rules[state] = append(rules[state][:rule], append(clone, rules[state][rule+1:]...)...) // nolint: makezero
	return nil
}

// Include rules from another state in this one.
func Include(state string) Rule {
	return Rule{Action: include{state}}
}

// StatefulDefinition is the lexer.Definition.
type StatefulDefinition struct {
	rules   compiledRules
	symbols map[string]TokenType
	// Map of key->*regexp.Regexp
	backrefCache sync.Map
	initialState string
	matchLongest bool
}

// MustStateful creates a new stateful lexer and panics if it is incorrect.
func MustStateful(rules Rules, options ...Option) *StatefulDefinition {
	def, err := New(rules, options...)
	if err != nil {
		panic(err)
	}
	return def
}

// New constructs a new stateful lexer from rules.
func New(rules Rules, options ...Option) (*StatefulDefinition, error) {
	compiled := compiledRules{}
	for key, set := range rules {
		for i, rule := range set {
			pattern := "^(?:" + rule.Pattern + ")"
			var (
				re  *regexp.Regexp
				err error
			)
			var match = backrefReplace.FindStringSubmatch(rule.Pattern)
			if match == nil || len(match[1])%2 == 0 {
				re, err = regexp.Compile(pattern)
				if err != nil {
					return nil, fmt.Errorf("%s.%d: %s", key, i, err)
				}
			}
			compiled[key] = append(compiled[key], compiledRule{
				Rule:   rule,
				ignore: len(rule.Name) > 0 && unicode.IsLower(rune(rule.Name[0])),
				RE:     re,
			})
		}
	}
restart:
	for state, rules := range compiled {
		for i, rule := range rules {
			if action, ok := rule.Action.(RulesAction); ok {
				if err := action.applyRules(state, i, compiled); err != nil {
					return nil, fmt.Errorf("%s.%d: %s", state, i, err)
				}
				goto restart
			}
		}
	}
	keys := make([]string, 0, len(compiled))
	for key := range compiled {
		keys = append(keys, key)
	}
	symbols := map[string]TokenType{
		"EOF": EOF,
	}
	sort.Strings(keys)
	duplicates := map[string]compiledRule{}
	rn := EOF - 1
	for _, key := range keys {
		for i, rule := range compiled[key] {
			if dup, ok := duplicates[rule.Name]; ok && rule.Pattern != dup.Pattern {
				panic(fmt.Sprintf("duplicate key %q with different patterns %q != %q", rule.Name, rule.Pattern, dup.Pattern))
			}
			duplicates[rule.Name] = rule
			compiled[key][i] = rule
			symbols[rule.Name] = rn
			rn--
		}
	}
	d := &StatefulDefinition{
		initialState: "Root",
		rules:        compiled,
		symbols:      symbols,
	}
	for _, option := range options {
		option(d)
	}
	return d, nil
}

// Rules returns the user-provided Rules used to construct the lexer.
func (d *StatefulDefinition) Rules() Rules {
	out := Rules{}
	for state, rules := range d.rules {
		for _, rule := range rules {
			out[state] = append(out[state], rule.Rule)
		}
	}
	return out
}

// LexString is a fast-path implementation for lexing strings.
func (d *StatefulDefinition) LexString(filename string, s string) (Lexer, error) {
	return &StatefulLexer{
		def:   d,
		data:  s,
		stack: []lexerState{{name: d.initialState}},
		pos: Position{
			Filename: filename,
			Line:     1,
			Column:   1,
		},
	}, nil
}

func (d *StatefulDefinition) Lex(filename string, r io.Reader) (Lexer, error) { // nolint: golint
	w := &strings.Builder{}
	_, err := io.Copy(w, r)
	if err != nil {
		return nil, err
	}
	return d.LexString(filename, w.String())
}

func (d *StatefulDefinition) Symbols() map[string]TokenType { // nolint: golint
	return d.symbols
}

type lexerState struct {
	name   string
	groups []string
}

// StatefulLexer implementation.
type StatefulLexer struct {
	stack []lexerState
	def   *StatefulDefinition
	data  string
	pos   Position
}

func (l *StatefulLexer) Next() (Token, error) { // nolint: golint
	parent := l.stack[len(l.stack)-1]
	rules := l.def.rules[parent.name]
next:
	for len(l.data) > 0 {
		var (
			rule  *compiledRule
			m     []int
			match []int
		)
		for i, candidate := range rules {
			// Special case "Return()".
			if candidate.Rule == ReturnRule {
				l.stack = l.stack[:len(l.stack)-1]
				parent = l.stack[len(l.stack)-1]
				rules = l.def.rules[parent.name]
				continue next
			}
			re, err := l.getPattern(candidate)
			if err != nil {
				return Token{}, errorf(l.pos, "rule %q: %s", candidate.Name, err)
			}
			m = re.FindStringSubmatchIndex(l.data)
			if m != nil && (match == nil || m[1] > match[1]) {
				match = m
				rule = &rules[i]
				if !l.def.matchLongest {
					break
				}
			}
		}
		if match == nil || rule == nil {
			sample := []rune(l.data)
			if len(sample) > 16 {
				sample = append(sample[:16], []rune("...")...)
			}
			return Token{}, errorf(l.pos, "invalid input text %q", string(sample))
		}

		if rule.Action != nil {
			groups := make([]string, 0, len(match)/2)
			for i := 0; i < len(match); i += 2 {
				groups = append(groups, l.data[match[i]:match[i+1]])
			}
			if err := rule.Action.applyAction(l, groups); err != nil {
				return Token{}, errorf(l.pos, "rule %q: %s", rule.Name, err)
			}
		} else if match[0] == match[1] {
			return Token{}, errorf(l.pos, "rule %q did not match any input", rule.Name)
		}

		span := l.data[match[0]:match[1]]
		l.data = l.data[match[1]:]
		// l.groups = groups

		// Update position.
		pos := l.pos
		l.pos.Advance(span)
		if rule.ignore {
			parent = l.stack[len(l.stack)-1]
			rules = l.def.rules[parent.name]
			continue
		}
		return Token{
			Type:  l.def.symbols[rule.Name],
			Value: span,
			Pos:   pos,
		}, nil
	}
	return EOFToken(l.pos), nil
}

func (l *StatefulLexer) getPattern(candidate compiledRule) (*regexp.Regexp, error) {
	if candidate.RE != nil {
		return candidate.RE, nil
	}

	// We don't have a compiled RE. This means there are back-references
	// that need to be substituted first.
	parent := l.stack[len(l.stack)-1]
	key := candidate.Pattern + "\000" + strings.Join(parent.groups, "\000")
	cached, ok := l.def.backrefCache.Load(key)
	if ok {
		return cached.(*regexp.Regexp), nil
	}

	var (
		re  *regexp.Regexp
		err error
	)
	pattern := backrefReplace.ReplaceAllStringFunc(candidate.Pattern, func(s string) string {
		var rematch = backrefReplace.FindStringSubmatch(s)
		n, nerr := strconv.ParseInt(rematch[2], 10, 64)
		if nerr != nil {
			err = nerr
			return s
		}
		if len(parent.groups) == 0 || int(n) >= len(parent.groups) {
			err = fmt.Errorf("invalid group %d from parent with %d groups", n, len(parent.groups))
			return s
		}
		// concatenate the leading \\\\ which are already escaped to the quoted match.
		return rematch[1][:len(rematch[1])-1] + regexp.QuoteMeta(parent.groups[n])
	})
	if err == nil {
		re, err = regexp.Compile("^(?:" + pattern + ")")
	}
	if err != nil {
		return nil, fmt.Errorf("invalid backref expansion: %q: %s", pattern, err)
	}
	l.def.backrefCache.Store(key, re)
	return re, nil
}
