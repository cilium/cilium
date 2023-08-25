package flect

import (
	"strings"
)

// Humanize returns first letter of sentence capitalized.
// Common acronyms are capitalized as well.
// Other capital letters in string are left as provided.
//	employee_salary = Employee salary
//	employee_id = employee ID
//	employee_mobile_number = Employee mobile number
//	first_Name = First Name
//	firstName = First Name
func Humanize(s string) string {
	return New(s).Humanize().String()
}

// Humanize First letter of sentence capitalized
func (i Ident) Humanize() Ident {
	if len(i.Original) == 0 {
		return New("")
	}

	parts := xappend([]string{}, Titleize(i.Parts[0]))
	if len(i.Parts) > 1 {
		parts = xappend(parts, i.Parts[1:]...)
	}

	return New(strings.Join(parts, " "))
}
