package vars

import (
	"bufio"
	"os"
	"regexp"
	"strings"
	"sync"
)

var (
	varsKeyValRgx = regexp.MustCompile(`\s*=\s*`)
	// varsLineRegx matches vars/envs of form "a =b c= $d    e=f g=${h}"
	varsLineRegx = regexp.MustCompile(`\w+\s*=\s*(\$?\{?)\w+(\}?)`)
)

// Variables stores a variable map that used for variable expansion
// in parsed commands and other parsed strings.
type Variables struct {
	sync.RWMutex
	err        error
	vars       map[string]string
	escapeChar rune
}

// New construction function to create a new Variables
func New() *Variables {
	return &Variables{vars: make(map[string]string), escapeChar: '\\'}
}

// WithEscapeChar sets the espacape char for the variable
func (v *Variables) WithEscapeChar(r rune) *Variables {
	v.escapeChar = r
	return v
}

// Err surfaces Variables error
func (v *Variables) Err() error {
	return v.err
}

// Envs declares process environment variables using
// a multi-line space-separated list of KEY=VAL format:
// i.e. GOOS=linux GOARCH=amd64
func (v *Variables) Envs(val string) *Variables {
	vars, err := v.parseVars(val)
	if err != nil {
		v.err = err
		return v
	}
	for key, value := range vars {
		if err := os.Setenv(key, v.ExpandVar(value, v.Val)); err != nil {
			v.err = err
			return v
		}
	}
	return v
}

// SetEnv sets a process environment variable.
func (v *Variables) SetEnv(name, value string) *Variables {
	if err := os.Setenv(name, v.ExpandVar(value, v.Val)); err != nil {
		v.err = err
		return v
	}
	return v
}

// Vars declares an internal variable used during current gexe session.
// It uses a multi-line, space-separated list of KEY=VAL format:
// i.e. foo=bar fuzz=buzz
func (v *Variables) Vars(val string) *Variables {
	vars, err := v.parseVars(val)

	if err != nil {
		v.err = err
		return v
	}

	// copy them
	v.Lock()
	defer v.Unlock()
	for key, val := range vars {
		v.vars[key] = val
	}

	return v
}

// SetVar declares an in-process local variable.
func (v *Variables) SetVar(name, value string) *Variables {
	v.Lock()
	defer v.Unlock()
	v.vars[name] = v.ExpandVar(value, v.Val)
	return v
}

// Val searches for a Var with provided key, if not found
// searches for environment var, for running process, with same key
func (v *Variables) Val(name string) string {
	//v.Lock()
	//defer v.Unlock()
	if val, ok := v.vars[name]; ok {
		return val
	}
	return os.Getenv(name)
}

// Eval returns the string str with its content expanded
// with variable values i.e. Eval("I am $HOME") returns
// "I am </user/home/path>"
func (v *Variables) Eval(str string) string {
	return v.ExpandVar(str, v.Val)
}

// parseVars parses multi-line, space-separated key=value pairs
// into map[string]string
func (v *Variables) parseVars(lines string) (map[string]string, error) {
	// parse lines into envs = []{"KEY0=VAL0", "KEY1=VAL1",...}
	var envs []string
	scnr := bufio.NewScanner(strings.NewReader(lines))

	for scnr.Scan() {
		envs = append(envs, varsLineRegx.FindAllString(scnr.Text(), -1)...)
	}
	if err := scnr.Err(); err != nil {
		return nil, err
	}

	// parse each item in []string{"key=value",...} item into key=value
	result := make(map[string]string)
	for _, env := range envs {
		kv := varsKeyValRgx.Split(env, 2)
		if len(kv) == 2 {
			result[kv[0]] = v.Eval(kv[1])
		}
	}

	return result, nil
}
