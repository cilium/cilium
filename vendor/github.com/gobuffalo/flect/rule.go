package flect

type ruleFn func(string) string

type rule struct {
	suffix string
	fn     ruleFn
}

func simpleRuleFunc(suffix, repl string) func(string) string {
	return func(s string) string {
		s = s[:len(s)-len(suffix)]
		return s + repl
	}
}

func noop(s string) string { return s }
