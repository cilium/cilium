package flect

var singularRules = []rule{}

// AddSingular adds a rule that will replace the given suffix with the replacement suffix.
func AddSingular(ext string, repl string) {
	singularMoot.Lock()
	defer singularMoot.Unlock()
	singularRules = append(singularRules, rule{
		suffix: ext,
		fn: func(s string) string {
			s = s[:len(s)-len(ext)]
			return s + repl
		},
	})

	singularRules = append(singularRules, rule{
		suffix: repl,
		fn: func(s string) string {
			return s
		},
	})
}
