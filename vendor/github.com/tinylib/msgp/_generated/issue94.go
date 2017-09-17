package _generated

import (
	"time"
)

//go:generate msgp

// Issue 94: shims were not propogated recursively,
// which caused shims that weren't at the top level
// to be silently ignored.
//
// The following line will generate an error after
// the code is generated if the generated code doesn't
// have the right identifier in it.

//go:generate ./search.sh $GOFILE timetostr

//msgp:shim time.Time as:string using:timetostr/strtotime
type T struct {
	T time.Time
}

func timetostr(t time.Time) string {
	return t.Format(time.RFC3339)
}

func strtotime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}
