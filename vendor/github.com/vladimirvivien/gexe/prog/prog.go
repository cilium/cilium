package prog

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Info returns information about the
// running program.
type Info struct {
	err error
}

// Prog is a constructor function that returns *Info
func Prog() *Info {
	return &Info{}
}

// Args returns a slice of the program arguments
func (p *Info) Args() []string {
	return os.Args
}

// Err returns the last generated error from a method call
func (p *Info) Err() error {
	return p.err
}

// Exit prints messages and exits current program
func (p *Info) Exit(code int, msgs ...string) {
	for _, msg := range msgs {
		fmt.Print(msg)
	}
	os.Exit(code)
}

// Pid program's process id
func (p *Info) Pid() int {
	return os.Getpid()
}

// Ppid program's parent process id
func (p *Info) Ppid() int {
	return os.Getppid()
}

// Path of running program
func (p *Info) Path() string {
	path, err := os.Executable()
	if err != nil {
		p.err = err
		return ""
	}
	return path
}

// Name of executable running
func (p *Info) Name() string {
	return filepath.Base(p.Path())
}

// Avail returns full path of binary name if available
func (p *Info) Avail(progName string) string {
	path, err := exec.LookPath(progName)
	if err != nil {
		p.err = err
		return ""
	}
	return path
}

// Workdir returns the working directory
func (p *Info) Workdir() string {
	path, err := os.Getwd()
	if err != nil {
		p.err = err
		return ""
	}
	return path
}
