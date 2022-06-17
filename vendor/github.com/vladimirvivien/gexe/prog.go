package gexe

import (
	"github.com/vladimirvivien/gexe/prog"
)

// Prog creates a new prog.Info to get information
// about the running program
func (e *Echo) Prog() *prog.Info {
	return e.prog
}
