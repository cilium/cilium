// Package gotenv provides functionality to dynamically load the environment variables
package gotenv

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const (
	// Pattern for detecting valid line format
	linePattern = `\A\s*(?:export\s+)?([\w\.]+)(?:\s*=\s*|:\s+?)('(?:\'|[^'])*'|"(?:\"|[^"])*"|[^#\n]+)?\s*(?:\s*\#.*)?\z`

	// Pattern for detecting valid variable within a value
	variablePattern = `(\\)?(\$)(\{?([A-Z0-9_]+)?\}?)`

	// Byte order mark character
	bom = "\xef\xbb\xbf"
)

// Env holds key/value pair of valid environment variable
type Env map[string]string

/*
Load is a function to load a file or multiple files and then export the valid variables into environment variables if they do not exist.
When it's called with no argument, it will load `.env` file on the current path and set the environment variables.
Otherwise, it will loop over the filenames parameter and set the proper environment variables.
*/
func Load(filenames ...string) error {
	return loadenv(false, filenames...)
}

/*
OverLoad is a function to load a file or multiple files and then export and override the valid variables into environment variables.
*/
func OverLoad(filenames ...string) error {
	return loadenv(true, filenames...)
}

/*
Must is wrapper function that will panic when supplied function returns an error.
*/
func Must(fn func(filenames ...string) error, filenames ...string) {
	if err := fn(filenames...); err != nil {
		panic(err.Error())
	}
}

/*
Apply is a function to load an io Reader then export the valid variables into environment variables if they do not exist.
*/
func Apply(r io.Reader) error {
	return parset(r, false)
}

/*
OverApply is a function to load an io Reader then export and override the valid variables into environment variables.
*/
func OverApply(r io.Reader) error {
	return parset(r, true)
}

func loadenv(override bool, filenames ...string) error {
	if len(filenames) == 0 {
		filenames = []string{".env"}
	}

	for _, filename := range filenames {
		f, err := os.Open(filename)
		if err != nil {
			return err
		}

		err = parset(f, override)
		if err != nil {
			return err
		}

		f.Close()
	}

	return nil
}

// parse and set :)
func parset(r io.Reader, override bool) error {
	env, err := strictParse(r, override)
	if err != nil {
		return err
	}

	for key, val := range env {
		setenv(key, val, override)
	}

	return nil
}

func setenv(key, val string, override bool) {
	if override {
		os.Setenv(key, val)
	} else {
		if _, present := os.LookupEnv(key); !present {
			os.Setenv(key, val)
		}
	}
}

// Parse is a function to parse line by line any io.Reader supplied and returns the valid Env key/value pair of valid variables.
// It expands the value of a variable from the environment variable but does not set the value to the environment itself.
// This function is skipping any invalid lines and only processing the valid one.
func Parse(r io.Reader) Env {
	env, _ := strictParse(r, false)
	return env
}

// StrictParse is a function to parse line by line any io.Reader supplied and returns the valid Env key/value pair of valid variables.
// It expands the value of a variable from the environment variable but does not set the value to the environment itself.
// This function is returning an error if there are any invalid lines.
func StrictParse(r io.Reader) (Env, error) {
	return strictParse(r, false)
}

func strictParse(r io.Reader, override bool) (Env, error) {
	env := make(Env)
	scanner := bufio.NewScanner(r)

	firstLine := true

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if firstLine {
			line = strings.TrimPrefix(line, bom)
			firstLine = false
		}

		if line == "" || line[0] == '#' {
			continue
		}

		quote := ""
		idx := strings.Index(line, "=")
		if idx == -1 {
			idx = strings.Index(line, ":")
		}
		if idx > 0 && idx < len(line)-1 {
			val := strings.TrimSpace(line[idx+1:])
			if val[0] == '"' || val[0] == '\'' {
				quote = val[:1]
				idx = strings.LastIndex(strings.TrimSpace(val[1:]), quote)
				if idx >= 0 && val[idx] != '\\' {
					quote = ""
				}
			}
		}
		for quote != "" && scanner.Scan() {
			l := scanner.Text()
			line += "\n" + l
			idx := strings.LastIndex(l, quote)
			if idx > 0 && l[idx-1] == '\\' {
				continue
			}
			if idx >= 0 {
				quote = ""
			}
		}

		if quote != "" {
			return env, fmt.Errorf("missing quotes")
		}

		err := parseLine(line, env, override)
		if err != nil {
			return env, err
		}
	}

	return env, nil
}

var (
	lineRgx     = regexp.MustCompile(linePattern)
	unescapeRgx = regexp.MustCompile(`\\([^$])`)
	varRgx      = regexp.MustCompile(variablePattern)
)

func parseLine(s string, env Env, override bool) error {
	rm := lineRgx.FindStringSubmatch(s)

	if len(rm) == 0 {
		return checkFormat(s, env)
	}

	key := rm[1]
	val := rm[2]

	// trim whitespace
	val = strings.TrimSpace(val)

	// determine if string has quote prefix
	hdq := strings.HasPrefix(val, `"`)

	// determine if string has single quote prefix
	hsq := strings.HasPrefix(val, `'`)

	// remove quotes '' or ""
	if l := len(val); (hsq || hdq) && l >= 2 {
		val = val[1 : l-1]
	}

	if hdq {
		val = strings.ReplaceAll(val, `\n`, "\n")
		val = strings.ReplaceAll(val, `\r`, "\r")

		// Unescape all characters except $ so variables can be escaped properly
		val = unescapeRgx.ReplaceAllString(val, "$1")
	}

	fv := func(s string) string {
		return varReplacement(s, hsq, env, override)
	}

	if !hsq {
		val = varRgx.ReplaceAllStringFunc(val, fv)
		val = parseVal(val, env, hdq, override)
	}

	env[key] = val
	return nil
}

func parseExport(st string, env Env) error {
	if strings.HasPrefix(st, "export") {
		vs := strings.SplitN(st, " ", 2)

		if len(vs) > 1 {
			if _, ok := env[vs[1]]; !ok {
				return fmt.Errorf("line `%s` has an unset variable", st)
			}
		}
	}

	return nil
}

var varNameRgx = regexp.MustCompile(`(\$)(\{?([A-Z0-9_]+)\}?)`)

func varReplacement(s string, hsq bool, env Env, override bool) string {
	if strings.HasPrefix(s, "\\") {
		return strings.TrimPrefix(s, "\\")
	}

	if hsq {
		return s
	}

	mn := varNameRgx.FindStringSubmatch(s)

	if len(mn) == 0 {
		return s
	}

	v := mn[3]

	if replace, ok := os.LookupEnv(v); ok && !override {
		return replace
	}

	replace, ok := env[v]
	if !ok {
		replace = os.Getenv(v)
	}

	return replace
}

func checkFormat(s string, env Env) error {
	st := strings.TrimSpace(s)

	if (st == "") || strings.HasPrefix(st, "#") {
		return nil
	}

	if err := parseExport(st, env); err != nil {
		return err
	}

	return fmt.Errorf("line `%s` doesn't match format", s)
}

func parseVal(val string, env Env, ignoreNewlines bool, override bool) string {
	if strings.Contains(val, "=") && !ignoreNewlines {
		kv := strings.Split(val, "\r")

		if len(kv) > 1 {
			val = kv[0]
			for _, l := range kv[1:] {
				_ = parseLine(l, env, override)
			}
		}
	}

	return val
}
