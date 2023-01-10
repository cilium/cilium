package lexer

// SimpleRule is a named regular expression.
type SimpleRule struct {
	Name    string
	Pattern string
}

// MustSimple creates a new Stateful lexer with only a single root state.
//
// It panics if there is an error.
func MustSimple(rules []SimpleRule, options ...Option) *StatefulDefinition {
	def, err := NewSimple(rules, options...)
	if err != nil {
		panic(err)
	}
	return def
}

// NewSimple creates a new Stateful lexer with only a single root state.
func NewSimple(rules []SimpleRule, options ...Option) (*StatefulDefinition, error) {
	fullRules := make([]Rule, len(rules))
	for i, rule := range rules {
		fullRules[i] = Rule{Name: rule.Name, Pattern: rule.Pattern}
	}
	return New(Rules{"Root": fullRules}, options...)
}
