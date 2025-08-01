package lexer

// SimpleRule is a named regular expression.
type SimpleRule struct {
	Name    string
	Pattern string
}

// MustSimple creates a new Stateful lexer with only a single root state.
// The rules are tried in order.
//
// It panics if there is an error.
func MustSimple(rules []SimpleRule) *StatefulDefinition {
	def, err := NewSimple(rules)
	if err != nil {
		panic(err)
	}
	return def
}

// NewSimple creates a new Stateful lexer with only a single root state.
// The rules are tried in order.
func NewSimple(rules []SimpleRule) (*StatefulDefinition, error) {
	fullRules := make([]Rule, len(rules))
	for i, rule := range rules {
		fullRules[i] = Rule{Name: rule.Name, Pattern: rule.Pattern}
	}
	return New(Rules{"Root": fullRules})
}
