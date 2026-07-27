package flect

import (
	"strings"
	"unicode"
)

// Underscore a string
//	bob dylan --> bob_dylan
//	Nice to see you! --> nice_to_see_you
//	widgetID --> widget_id
func Underscore(s string) string {
	return New(s).Underscore().String()
}

// Underscore a string
//	bob dylan --> bob_dylan
//	Nice to see you! --> nice_to_see_you
//	widgetID --> widget_id
func (i Ident) Underscore() Ident {
	out := make([]string, 0, len(i.Parts))
	for _, part := range i.Parts {
		var x strings.Builder
		x.Grow(len(part))
		for _, c := range part {
			if unicode.IsLetter(c) || unicode.IsDigit(c) {
				x.WriteRune(c)
			}
		}
		if x.Len() > 0 {
			out = append(out, x.String())
		}
	}
	return New(strings.ToLower(strings.Join(out, "_")))
}
