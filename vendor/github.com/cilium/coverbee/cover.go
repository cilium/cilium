// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found at https://raw.githubusercontent.com/golang/go/master/LICENSE.

package coverbee

import (
	"bufio"
	"bytes"
	"fmt"
	"html/template"
	"io"
	"math"
	"os"
	"sort"
	"strings"

	"golang.org/x/tools/cover"
)

// HTMLOutput generates an HTML page from profile data.
// coverage report is written to the out writer.
func HTMLOutput(profiles []*cover.Profile, out io.Writer) error {
	var d templateData

	for _, profile := range profiles {
		if profile.Mode == "set" {
			d.Set = true
		}

		src, err := os.ReadFile(profile.FileName)
		if err != nil {
			return fmt.Errorf("can't read %q: %v", profile.FileName, err)
		}

		var buf strings.Builder
		err = htmlGen(&buf, src, profile.Boundaries(src))
		if err != nil {
			return err
		}
		d.Files = append(d.Files, &templateFile{
			Name: profile.FileName,
			//#nosec G203 HTML escaping doesn't seem like an issue here
			Body:     template.HTML(buf.String()),
			Coverage: percentCovered(profile),
		})
	}

	err := htmlTemplate.Execute(out, d)
	if err != nil {
		return err
	}

	return nil
}

// percentCovered returns, as a percentage, the fraction of the statements in
// the profile covered by the test run.
// In effect, it reports the coverage of a given source file.
func percentCovered(p *cover.Profile) float64 {
	var total, covered int64
	for _, b := range p.Blocks {
		total += int64(b.NumStmt)
		if b.Count > 0 {
			covered += int64(b.NumStmt)
		}
	}
	if total == 0 {
		return 0
	}
	return float64(covered) / float64(total) * 100
}

// htmlGen generates an HTML coverage report with the provided filename,
// source code, and tokens, and writes it to the given Writer.
func htmlGen(w io.Writer, src []byte, boundaries []cover.Boundary) error {
	dst := bufio.NewWriter(w)
	for i := range src {
		for len(boundaries) > 0 && boundaries[0].Offset == i {
			b := boundaries[0]
			if b.Start {
				n := 0
				if b.Count > 0 {
					n = int(math.Floor(b.Norm*9)) + 1
				}
				fmt.Fprintf(dst, `<span class="cov%v" title="%v">`, n, b.Count)
			} else {
				//nolint:errcheck // no remediation available if writes were to fail
				_, _ = dst.WriteString("</span>")
			}
			boundaries = boundaries[1:]
		}

		//nolint:errcheck // no remediation available if writes were to fail
		switch b := src[i]; b {
		case '>':
			_, _ = dst.WriteString("&gt;")
		case '<':
			_, _ = dst.WriteString("&lt;")
		case '&':
			_, _ = dst.WriteString("&amp;")
		case '\t':
			_, _ = dst.WriteString("        ")
		default:
			_ = dst.WriteByte(b)
		}
	}
	return dst.Flush()
}

// rgb returns an rgb value for the specified coverage value
// between 0 (no coverage) and 10 (max coverage).
func rgb(n int) string {
	if n == 0 {
		return "rgb(192, 0, 0)" // Red
	}
	// Gradient from gray to green.
	r := 128 - 12*(n-1)
	g := 128 + 12*(n-1)
	b := 128 + 3*(n-1)
	return fmt.Sprintf("rgb(%v, %v, %v)", r, g, b)
}

// colors generates the CSS rules for coverage colors.
func colors() template.CSS {
	var buf bytes.Buffer
	for i := 0; i < 11; i++ {
		fmt.Fprintf(&buf, ".cov%v { color: %v }\n", i, rgb(i))
	}
	return template.CSS(buf.String())
}

var htmlTemplate = template.Must(template.New("html").Funcs(template.FuncMap{
	"colors": colors,
}).Parse(tmplHTML))

type templateData struct {
	Files []*templateFile
	Set   bool
}

// PackageName returns a name for the package being shown.
// It does this by choosing the penultimate element of the path
// name, so foo.bar/baz/foo.go chooses 'baz'. This is cheap
// and easy, avoids parsing the Go file, and gets a better answer
// for package main. It returns the empty string if there is
// a problem.
func (td templateData) PackageName() string {
	if len(td.Files) == 0 {
		return ""
	}
	fileName := td.Files[0].Name
	elems := strings.Split(fileName, "/") // Package path is always slash-separated.
	// Return the penultimate non-empty element.
	for i := len(elems) - 2; i >= 0; i-- {
		if elems[i] != "" {
			return elems[i]
		}
	}
	return ""
}

type templateFile struct {
	Name     string
	Body     template.HTML
	Coverage float64
}

const tmplHTML = `
<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
		<title>{{$pkg := .PackageName}}{{if $pkg}}{{$pkg}}: {{end}}Go Coverage Report</title>
		<style>
			body {
				background: black;
				color: rgb(80, 80, 80);
			}
			body, pre, #legend span {
				font-family: Menlo, monospace;
				font-weight: bold;
			}
			#topbar {
				background: black;
				position: fixed;
				top: 0; left: 0; right: 0;
				height: 42px;
				border-bottom: 1px solid rgb(80, 80, 80);
			}
			#content {
				margin-top: 50px;
			}
			#nav, #legend {
				float: left;
				margin-left: 10px;
			}
			#legend {
				margin-top: 12px;
			}
			#nav {
				margin-top: 10px;
			}
			#legend span {
				margin: 0 5px;
			}
			{{colors}}
		</style>
	</head>
	<body>
		<div id="topbar">
			<div id="nav">
				<select id="files">
				{{range $i, $f := .Files}}
				<option value="file{{$i}}">{{$f.Name}} ({{printf "%.1f" $f.Coverage}}%)</option>
				{{end}}
				</select>
			</div>
			<div id="legend">
				<span>not tracked</span>
			{{if .Set}}
				<span class="cov0">not covered</span>
				<span class="cov8">covered</span>
			{{else}}
				<span class="cov0">no coverage</span>
				<span class="cov1">low coverage</span>
				<span class="cov2">*</span>
				<span class="cov3">*</span>
				<span class="cov4">*</span>
				<span class="cov5">*</span>
				<span class="cov6">*</span>
				<span class="cov7">*</span>
				<span class="cov8">*</span>
				<span class="cov9">*</span>
				<span class="cov10">high coverage</span>
			{{end}}
			</div>
		</div>
		<div id="content">
		{{range $i, $f := .Files}}
		<pre class="file" id="file{{$i}}" style="display: none">{{$f.Body}}</pre>
		{{end}}
		</div>
	</body>
	<script>
	(function() {
		var files = document.getElementById('files');
		var visible;
		files.addEventListener('change', onChange, false);
		function select(part) {
			if (visible)
				visible.style.display = 'none';
			visible = document.getElementById(part);
			if (!visible)
				return;
			files.value = part;
			visible.style.display = 'block';
			location.hash = part;
		}
		function onChange() {
			select(files.value);
			window.scrollTo(0, 0);
		}
		if (location.hash != "") {
			select(location.hash.substr(1));
		}
		if (!visible) {
			select("file0");
		}
	})();
	</script>
</html>
`

// CoverBlock wraps the ProfileBlock, adding a filename so each CoverBlock can be turned into a line on a go coverage
// file.
type CoverBlock struct {
	Filename     string
	ProfileBlock cover.ProfileBlock
}

func (cb CoverBlock) String() string {
	return fmt.Sprintf(
		"%s:%d.%d,%d.%d %d %d",
		cb.Filename,
		cb.ProfileBlock.StartLine,
		cb.ProfileBlock.StartCol,
		cb.ProfileBlock.EndLine,
		cb.ProfileBlock.EndCol,
		cb.ProfileBlock.NumStmt,
		cb.ProfileBlock.Count,
	)
}

// BlockListToGoCover convert a block-list into a go-cover file which can be interpreted by `go tool cover`.
// `mode` value can be `set` or `count`, see `go tool cover -h` for details.
func BlockListToGoCover(blockList [][]CoverBlock, out io.Writer, mode string) {
	fmt.Fprintln(out, "mode:", mode)
	for _, coverBlock := range blockList {
		for _, line := range coverBlock {
			fmt.Fprintln(out, line)
		}
	}
}

// ProfilesToGoCover convert a profile list into a go-cover file which can be interpreted by `go tool cover`.
// `mode` value can be `set` or `count`, see `go tool cover -h` for details.
func ProfilesToGoCover(profiles []*cover.Profile, out io.Writer, mode string) {
	fmt.Fprintln(out, "mode:", mode)
	for _, profile := range profiles {
		for _, block := range profile.Blocks {
			fmt.Fprintf(out,
				"%s:%d.%d,%d.%d %d %d\n",
				profile.FileName,
				block.StartLine,
				block.StartCol,
				block.EndLine,
				block.EndCol,
				block.NumStmt,
				block.Count,
			)
		}
	}
}

// BlockListToHTML converts a block-list into a HTML coverage report.
func BlockListToHTML(blockList [][]CoverBlock, out io.Writer, mode string) error {
	var buf bytes.Buffer
	BlockListToGoCover(blockList, &buf, mode)
	profiles, err := cover.ParseProfilesFromReader(&buf)
	if err != nil {
		return err
	}

	if err = HTMLOutput(profiles, out); err != nil {
		return fmt.Errorf("write html: %w", err)
	}

	return nil
}

// BlockListFilePaths returns a sorted and deduplicateed list of file paths included in the block list
func BlockListFilePaths(blockList [][]CoverBlock) []string {
	var uniqueFiles []string
	for _, blocks := range blockList {
		for _, block := range blocks {
			i := sort.SearchStrings(uniqueFiles, block.Filename)
			if i < len(uniqueFiles) && uniqueFiles[i] == block.Filename {
				continue
			}

			// Insert sorted
			uniqueFiles = append(uniqueFiles, "")
			copy(uniqueFiles[i+1:], uniqueFiles[i:])
			uniqueFiles[i] = block.Filename
		}
	}
	return uniqueFiles
}

// Check for:
// aaaaa
//
//	bbbbb
//
// -----
//
//	aaaa
//
// bbbb
// -----
//
//	aaa
//
// bbbbbbb
// -----
// aaaaaaa
//
//	bbb
func blocksOverlap(a, b cover.ProfileBlock) bool {
	return (blockLTE(a.StartLine, a.StartCol, b.EndLine, b.EndCol) &&
		blockGTE(a.EndLine, a.EndCol, b.EndLine, b.EndCol)) ||
		(blockLTE(a.StartLine, a.StartCol, b.StartLine, b.StartCol) &&
			blockGTE(a.EndLine, a.EndCol, b.StartLine, b.StartCol)) ||
		(blockGTE(a.StartLine, a.StartCol, b.StartLine, b.StartCol) &&
			blockLTE(a.EndLine, a.EndCol, b.EndLine, b.EndCol))
}

// a <= b
func blockLTE(aLine, aCol, bLine, bCol int) bool {
	if aLine == bLine {
		return aCol <= bCol
	}

	return aLine < bLine
}

// a >= b
func blockGTE(aLine, aCol, bLine, bCol int) bool {
	if aLine == bLine {
		return aCol >= bCol
	}

	return aLine > bLine
}
