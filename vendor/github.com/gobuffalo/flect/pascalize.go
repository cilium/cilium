package flect

import (
	"strings"
)

// Pascalize returns a string with each segment capitalized
//	user = User
//	bob dylan = BobDylan
//	widget_id = WidgetID
func Pascalize(s string) string {
	return New(s).Pascalize().String()
}

// Pascalize returns a string with each segment capitalized
//	user = User
//	bob dylan = BobDylan
//	widget_id = WidgetID
func (i Ident) Pascalize() Ident {
	c := i.Camelize()
	if len(c.String()) == 0 {
		return c
	}
	if len(i.Parts) == 0 {
		return i
	}
	capLen := 1
	if _, ok := baseAcronyms[strings.ToUpper(i.Parts[0])]; ok {
		capLen = len(i.Parts[0])
	}
	return New(string(strings.ToUpper(c.Original[0:capLen])) + c.Original[capLen:])
}
