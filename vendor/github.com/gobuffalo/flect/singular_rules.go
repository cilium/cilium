package flect

var singularRules = []rule{}

// AddSingular adds a rule that will replace the given suffix with the replacement suffix.
// The name is confusing. This function will be deprecated in the next release.
func AddSingular(ext string, repl string) {
	InsertSingularRule(ext, repl)
}

// InsertSingularRule inserts a rule that will replace the given suffix with
// the repl(acement) at the beginning of the list of the singularize rules.
func InsertSingularRule(suffix, repl string) {
	singularMoot.Lock()
	defer singularMoot.Unlock()

	singularRules = append([]rule{{
		suffix: suffix,
		fn:     simpleRuleFunc(suffix, repl),
	}}, singularRules...)

	singularRules = append([]rule{{
		suffix: repl,
		fn:     noop,
	}}, singularRules...)
}
