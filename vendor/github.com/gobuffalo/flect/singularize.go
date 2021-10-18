package flect

import (
	"strings"
	"sync"
)

var singularMoot = &sync.RWMutex{}

// Singularize returns a singular version of the string
//	users = user
//	data = datum
//	people = person
func Singularize(s string) string {
	return New(s).Singularize().String()
}

// SingularizeWithSize will singular a string taking a number number into account.
//	SingularizeWithSize("user", 1) = user
//	SingularizeWithSize("user", 2) = users
func SingularizeWithSize(s string, i int) string {
	if i == 1 || i == -1 {
		return New(s).Singularize().String()
	}
	return New(s).Pluralize().String()
}

// Singularize returns a singular version of the string
//	users = user
//	data = datum
//	people = person
func (i Ident) Singularize() Ident {
	s := i.Original
	if len(s) == 0 {
		return i
	}

	singularMoot.RLock()
	defer singularMoot.RUnlock()
	ls := strings.ToLower(s)
	if p, ok := pluralToSingle[ls]; ok {
		return New(p)
	}
	if _, ok := singleToPlural[ls]; ok {
		return i
	}
	for _, r := range singularRules {
		if strings.HasSuffix(ls, r.suffix) {
			return New(r.fn(s))
		}
	}

	if strings.HasSuffix(s, "s") {
		return New(s[:len(s)-1])
	}
	return i
}
