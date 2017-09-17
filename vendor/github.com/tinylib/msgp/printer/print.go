package printer

import (
	"bytes"
	"fmt"
	"github.com/tinylib/msgp/gen"
	"github.com/tinylib/msgp/parse"
	"github.com/ttacon/chalk"
	"golang.org/x/tools/imports"
	"io"
	"io/ioutil"
	"strings"
)

func infof(s string, v ...interface{}) {
	fmt.Printf(chalk.Magenta.Color(s), v...)
}

// PrintFile prints the methods for the provided list
// of elements to the given file name and canonical
// package path.
func PrintFile(file string, f *parse.FileSet, mode gen.Method) error {
	out, tests, err := generate(f, mode)
	if err != nil {
		return err
	}

	// we'll run goimports on the main file
	// in another goroutine, and run it here
	// for the test file. empirically, this
	// takes about the same amount of time as
	// doing them in serial when GOMAXPROCS=1,
	// and faster otherwise.
	res := goformat(file, out.Bytes())
	if tests != nil {
		testfile := strings.TrimSuffix(file, ".go") + "_test.go"
		err = format(testfile, tests.Bytes())
		if err != nil {
			return err
		}
		infof(">>> Wrote and formatted \"%s\"\n", testfile)
	}
	err = <-res
	if err != nil {
		return err
	}
	return nil
}

func format(file string, data []byte) error {
	out, err := imports.Process(file, data, nil)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, out, 0600)
}

func goformat(file string, data []byte) <-chan error {
	out := make(chan error, 1)
	go func(file string, data []byte, end chan error) {
		end <- format(file, data)
		infof(">>> Wrote and formatted \"%s\"\n", file)
	}(file, data, out)
	return out
}

func dedupImports(imp []string) []string {
	m := make(map[string]struct{})
	for i := range imp {
		m[imp[i]] = struct{}{}
	}
	r := []string{}
	for k := range m {
		r = append(r, k)
	}
	return r
}

func generate(f *parse.FileSet, mode gen.Method) (*bytes.Buffer, *bytes.Buffer, error) {
	outbuf := bytes.NewBuffer(make([]byte, 0, 4096))
	writePkgHeader(outbuf, f.Package)

	myImports := []string{"github.com/tinylib/msgp/msgp"}
	for _, imp := range f.Imports {
		if imp.Name != nil {
			// have an alias, include it.
			myImports = append(myImports, imp.Name.Name+` `+imp.Path.Value)
		} else {
			myImports = append(myImports, imp.Path.Value)
		}
	}
	dedup := dedupImports(myImports)
	writeImportHeader(outbuf, dedup...)

	var testbuf *bytes.Buffer
	var testwr io.Writer
	if mode&gen.Test == gen.Test {
		testbuf = bytes.NewBuffer(make([]byte, 0, 4096))
		writePkgHeader(testbuf, f.Package)
		if mode&(gen.Encode|gen.Decode) != 0 {
			writeImportHeader(testbuf, "bytes", "github.com/tinylib/msgp/msgp", "testing")
		} else {
			writeImportHeader(testbuf, "github.com/tinylib/msgp/msgp", "testing")
		}
		testwr = testbuf
	}
	return outbuf, testbuf, f.PrintTo(gen.NewPrinter(mode, outbuf, testwr))
}

func writePkgHeader(b *bytes.Buffer, name string) {
	b.WriteString("package ")
	b.WriteString(name)
	b.WriteByte('\n')
	b.WriteString("// NOTE: THIS FILE WAS PRODUCED BY THE\n// MSGP CODE GENERATION TOOL (github.com/tinylib/msgp)\n// DO NOT EDIT\n\n")
}

func writeImportHeader(b *bytes.Buffer, imports ...string) {
	b.WriteString("import (\n")
	for _, im := range imports {
		if im[len(im)-1] == '"' {
			// support aliased imports
			fmt.Fprintf(b, "\t%s\n", im)
		} else {
			fmt.Fprintf(b, "\t%q\n", im)
		}
	}
	b.WriteString(")\n\n")
}
