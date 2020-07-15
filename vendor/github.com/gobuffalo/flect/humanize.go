package flect

import (
	"strings"
)

// Humanize returns first letter of sentence capitalized.
// Common acronyms are capitalized as well.
// Other capital letters in string are left as provided.
// employee_salary = Employee salary
// employee_id = employee ID
// employee_mobile_number = Employee mobile number
// first_Name = First Name
// firstName = First Name
func Humanize(s string) string {
	return New(s).Humanize().String()
}

// Humanize First letter of sentence capitalized
func (i Ident) Humanize() Ident {
	if len(i.Original) == 0 {
		return New("")
	}

	var parts []string
	for index, part := range i.Parts {
		if index == 0 {
			part = strings.Title(i.Parts[0])
		}

		parts = xappend(parts, part)
	}

	return New(strings.Join(parts, " "))
}
