// Copyright (c) 2012-2015 Ugorji Nwoke. All rights reserved.
// Use of this source code is governed by a MIT license found in the LICENSE file.

// codecgen generates codec.Selfer implementations for a set of types.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"
)

const genCodecPkg = "codec1978" // keep this in sync with codec.genCodecPkg

const genFrunMainTmpl = `//+build ignore

package main
{{ if .Types }}import "{{ .ImportPath }}"{{ end }}
func main() {
	{{ $.PackageName }}.CodecGenTempWrite{{ .RandString }}()
}
`

// const genFrunPkgTmpl = `//+build codecgen
const genFrunPkgTmpl = `
package {{ $.PackageName }}

import (
	{{ if not .CodecPkgFiles }}{{ .CodecPkgName }} "{{ .CodecImportPath }}"{{ end }}
	"os"
	"reflect"
	"bytes"
	"strings"
	"go/format"
)

func CodecGenTempWrite{{ .RandString }}() {
	fout, err := os.Create("{{ .OutFile }}")
	if err != nil {
		panic(err)
	}
	defer fout.Close()
	var out bytes.Buffer
	
	var typs []reflect.Type 
{{ range $index, $element := .Types }}
	var t{{ $index }} {{ . }}
	typs = append(typs, reflect.TypeOf(t{{ $index }}))
{{ end }}
	{{ if not .CodecPkgFiles }}{{ .CodecPkgName }}.{{ end }}Gen(&out, "{{ .BuildTag }}", "{{ .PackageName }}", "{{ .RandString }}", {{ .UseUnsafe }}, {{ if not .CodecPkgFiles }}{{ .CodecPkgName }}.{{ end }}NewTypeInfos(strings.Split("{{ .StructTags }}", ",")), typs...)
	bout, err := format.Source(out.Bytes())
	if err != nil {
		fout.Write(out.Bytes())
		panic(err)
	}
	fout.Write(bout)
}

`

// Generate is given a list of *.go files to parse, and an output file (fout).
//
// It finds all types T in the files, and it creates 2 tmp files (frun).
//   - main package file passed to 'go run'
//   - package level file which calls *genRunner.Selfer to write Selfer impls for each T.
// We use a package level file so that it can reference unexported types in the package being worked on.
// Tool then executes: "go run __frun__" which creates fout.
// fout contains Codec(En|De)codeSelf implementations for every type T.
//
func Generate(outfile, buildTag, codecPkgPath string, uid int64, useUnsafe bool, goRunTag string,
	st string, regexName *regexp.Regexp, notRegexName *regexp.Regexp, deleteTempFile bool, infiles ...string) (err error) {
	// For each file, grab AST, find each type, and write a call to it.
	if len(infiles) == 0 {
		return
	}
	if outfile == "" || codecPkgPath == "" {
		err = errors.New("outfile and codec package path cannot be blank")
		return
	}
	if uid < 0 {
		uid = -uid
	}
	if uid == 0 {
		rr := rand.New(rand.NewSource(time.Now().UnixNano()))
		uid = 101 + rr.Int63n(9777)
	}
	// We have to parse dir for package, before opening the temp file for writing (else ImportDir fails).
	// Also, ImportDir(...) must take an absolute path.
	lastdir := filepath.Dir(outfile)
	absdir, err := filepath.Abs(lastdir)
	if err != nil {
		return
	}
	pkg, err := build.Default.ImportDir(absdir, build.AllowBinary)
	if err != nil {
		return
	}
	type tmplT struct {
		CodecPkgName    string
		CodecImportPath string
		ImportPath      string
		OutFile         string
		PackageName     string
		RandString      string
		BuildTag        string
		StructTags      string
		Types           []string
		CodecPkgFiles   bool
		UseUnsafe       bool
	}
	tv := tmplT{
		CodecPkgName:    genCodecPkg,
		OutFile:         outfile,
		CodecImportPath: codecPkgPath,
		BuildTag:        buildTag,
		UseUnsafe:       useUnsafe,
		RandString:      strconv.FormatInt(uid, 10),
		StructTags:      st,
	}
	tv.ImportPath = pkg.ImportPath
	if tv.ImportPath == tv.CodecImportPath {
		tv.CodecPkgFiles = true
		tv.CodecPkgName = "codec"
	} else {
		// HACK: always handle vendoring. It should be typically on in go 1.6, 1.7
		s := tv.ImportPath
		const vendorStart = "vendor/"
		const vendorInline = "/vendor/"
		if i := strings.LastIndex(s, vendorInline); i >= 0 {
			tv.ImportPath = s[i+len(vendorInline):]
		} else if strings.HasPrefix(s, vendorStart) {
			tv.ImportPath = s[len(vendorStart):]
		}
	}
	astfiles := make([]*ast.File, len(infiles))
	for i, infile := range infiles {
		if filepath.Dir(infile) != lastdir {
			err = errors.New("in files must all be in same directory as outfile")
			return
		}
		fset := token.NewFileSet()
		astfiles[i], err = parser.ParseFile(fset, infile, nil, 0)
		if err != nil {
			return
		}
		if i == 0 {
			tv.PackageName = astfiles[i].Name.Name
			if tv.PackageName == "main" {
				// codecgen cannot be run on types in the 'main' package.
				// A temporary 'main' package must be created, and should reference the fully built
				// package containing the types.
				// Also, the temporary main package will conflict with the main package which already has a main method.
				err = errors.New("codecgen cannot be run on types in the 'main' package")
				return
			}
		}
	}

	// keep track of types with selfer methods
	// selferMethods := []string{"CodecEncodeSelf", "CodecDecodeSelf"}
	selferEncTyps := make(map[string]bool)
	selferDecTyps := make(map[string]bool)
	for _, f := range astfiles {
		for _, d := range f.Decls {
			// if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv != nil && fd.Recv.NumFields() == 1 {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv != nil && len(fd.Recv.List) == 1 {
				recvType := fd.Recv.List[0].Type
				if ptr, ok := recvType.(*ast.StarExpr); ok {
					recvType = ptr.X
				}
				if id, ok := recvType.(*ast.Ident); ok {
					switch fd.Name.Name {
					case "CodecEncodeSelf":
						selferEncTyps[id.Name] = true
					case "CodecDecodeSelf":
						selferDecTyps[id.Name] = true
					}
				}
			}
		}
	}

	// now find types
	for _, f := range astfiles {
		for _, d := range f.Decls {
			if gd, ok := d.(*ast.GenDecl); ok {
				for _, dd := range gd.Specs {
					if td, ok := dd.(*ast.TypeSpec); ok {
						// if len(td.Name.Name) == 0 || td.Name.Name[0] > 'Z' || td.Name.Name[0] < 'A' {
						if len(td.Name.Name) == 0 {
							continue
						}

						// only generate for:
						//   struct: StructType
						//   primitives (numbers, bool, string): Ident
						//   map: MapType
						//   slice, array: ArrayType
						//   chan: ChanType
						// do not generate:
						//   FuncType, InterfaceType, StarExpr (ptr), etc
						switch td.Type.(type) {
						case *ast.StructType, *ast.Ident, *ast.MapType, *ast.ArrayType, *ast.ChanType:
							// only add to tv.Types iff
							//   - it matches per the -r parameter
							//   - it doesn't match per the -nr parameter
							//   - it doesn't have any of the Selfer methods in the file
							if regexName.FindStringIndex(td.Name.Name) != nil &&
								notRegexName.FindStringIndex(td.Name.Name) == nil &&
								!selferEncTyps[td.Name.Name] &&
								!selferDecTyps[td.Name.Name] {
								tv.Types = append(tv.Types, td.Name.Name)
							}
						}
					}
				}
			}
		}
	}

	if len(tv.Types) == 0 {
		return
	}

	// we cannot use ioutil.TempFile, because we cannot guarantee the file suffix (.go).
	// Also, we cannot create file in temp directory,
	// because go run will not work (as it needs to see the types here).
	// Consequently, create the temp file in the current directory, and remove when done.

	// frun, err = ioutil.TempFile("", "codecgen-")
	// frunName := filepath.Join(os.TempDir(), "codecgen-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".go")

	frunMainName := "codecgen-main-" + tv.RandString + ".generated.go"
	frunPkgName := "codecgen-pkg-" + tv.RandString + ".generated.go"
	if deleteTempFile {
		defer os.Remove(frunMainName)
		defer os.Remove(frunPkgName)
	}
	// var frunMain, frunPkg *os.File
	if _, err = gen1(frunMainName, genFrunMainTmpl, &tv); err != nil {
		return
	}
	if _, err = gen1(frunPkgName, genFrunPkgTmpl, &tv); err != nil {
		return
	}

	// remove outfile, so "go run ..." will not think that types in outfile already exist.
	os.Remove(outfile)

	// execute go run frun
	cmd := exec.Command("go", "run", "-tags="+goRunTag, frunMainName) //, frunPkg.Name())
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err = cmd.Run(); err != nil {
		err = fmt.Errorf("error running 'go run %s': %v, console: %s",
			frunMainName, err, buf.Bytes())
		return
	}
	os.Stdout.Write(buf.Bytes())
	return
}

func gen1(frunName, tmplStr string, tv interface{}) (frun *os.File, err error) {
	os.Remove(frunName)
	if frun, err = os.Create(frunName); err != nil {
		return
	}
	defer frun.Close()

	t := template.New("")
	if t, err = t.Parse(tmplStr); err != nil {
		return
	}
	bw := bufio.NewWriter(frun)
	if err = t.Execute(bw, tv); err != nil {
		return
	}
	if err = bw.Flush(); err != nil {
		return
	}
	return
}

func main() {
	o := flag.String("o", "", "out file")
	c := flag.String("c", genCodecPath, "codec path")
	t := flag.String("t", "", "build tag to put in file")
	r := flag.String("r", ".*", "regex for type name to match")
	nr := flag.String("nr", "^$", "regex for type name to exclude")
	rt := flag.String("rt", "", "tags for go run")
	st := flag.String("st", "codec,json", "struct tag keys to introspect")
	x := flag.Bool("x", false, "keep temp file")
	u := flag.Bool("u", false, "Use unsafe, e.g. to avoid unnecessary allocation on []byte->string")
	d := flag.Int64("d", 0, "random identifier for use in generated code")
	flag.Parse()
	if err := Generate(*o, *t, *c, *d, *u, *rt, *st,
		regexp.MustCompile(*r), regexp.MustCompile(*nr), !*x, flag.Args()...); err != nil {
		fmt.Fprintf(os.Stderr, "codecgen error: %v\n", err)
		os.Exit(1)
	}
}
