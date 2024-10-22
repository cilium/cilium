package flect

import "unicode"

// Capitalize will cap the first letter of string
//	user = User
//	bob dylan = Bob dylan
//	widget_id = Widget_id
func Capitalize(s string) string {
	return New(s).Capitalize().String()
}

// Capitalize will cap the first letter of string
//	user = User
//	bob dylan = Bob dylan
//	widget_id = Widget_id
func (i Ident) Capitalize() Ident {
	if len(i.Parts) == 0 {
		return New("")
	}
	runes := []rune(i.Original)
	runes[0] = unicode.ToTitle(runes[0])
	return New(string(runes))
}
