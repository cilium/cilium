package flect

import (
	"strings"
	"sync"
)

var pluralMoot = &sync.RWMutex{}

// Pluralize returns a plural version of the string
//	user = users
//	person = people
//	datum = data
func Pluralize(s string) string {
	return New(s).Pluralize().String()
}

// PluralizeWithSize will pluralize a string taking a number number into account.
//	PluralizeWithSize("user", 1) = user
//	PluralizeWithSize("user", 2) = users
func PluralizeWithSize(s string, i int) string {
	if i == 1 || i == -1 {
		return New(s).Singularize().String()
	}
	return New(s).Pluralize().String()
}

// Pluralize returns a plural version of the string
//	user = users
//	person = people
//	datum = data
func (i Ident) Pluralize() Ident {
	s := i.LastPart()
	if len(s) == 0 {
		return New("")
	}

	pluralMoot.RLock()
	defer pluralMoot.RUnlock()

	ls := strings.ToLower(s)
	if _, ok := pluralToSingle[ls]; ok {
		return i
	}
	if p, ok := singleToPlural[ls]; ok {
		if s == Capitalize(s) {
			p = Capitalize(p)
		}
		return i.ReplaceSuffix(s, p)
	}
	for _, r := range pluralRules {
		if strings.HasSuffix(ls, r.suffix) {
			return i.ReplaceSuffix(s, r.fn(s))
		}
	}

	if strings.HasSuffix(ls, "s") {
		return i
	}

	return New(i.String() + "s")
}
