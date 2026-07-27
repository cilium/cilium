package pretty

import (
	"bytes"
	"fmt"
	"io"

	"github.com/fatih/color"
)

// NB(directxman12): this isn't particularly elegant, but it's also
// sufficiently simple as to be maintained here.   Man (roff) would've
// probably worked, but it's not necessarily on Windows by default.

// Span is a chunk of content that is writable to an output, but knows how to
// calculate its apparent visual "width" on the terminal (not to be confused
// with the raw length, which may include zero-width coloring sequences).
type Span interface {
	// VisualLength reports the "width" as perceived by the user on the terminal
	// (i.e. widest line, ignoring ANSI escape characters).
	VisualLength() int
	// WriteTo writes the full span contents to the given writer.
	WriteTo(io.Writer) error
}

// Table is a Span that writes its data in table form, with sizing controlled
// by the given table calculator.  Rows are started with StartRow, followed by
// some calls to Column, followed by a call to EndRow.  Once all rows are
// added, the table can be used as a Span.
type Table struct {
	Sizing *TableCalculator

	cellsByRow [][]Span
	colSizes   []int
}

// StartRow starts a new row.
// It must eventually be followed by EndRow.
func (t *Table) StartRow() {
	t.cellsByRow = append(t.cellsByRow, []Span(nil))
}

// EndRow ends the currently started row.
func (t *Table) EndRow() {
	lastRow := t.cellsByRow[len(t.cellsByRow)-1]
	sizes := make([]int, len(lastRow))
	for i, cell := range lastRow {
		sizes[i] = cell.VisualLength()
	}
	t.Sizing.AddRowSizes(sizes...)
}

// Column adds the given span as a new column to the current row.
func (t *Table) Column(contents Span) {
	currentRowInd := len(t.cellsByRow) - 1
	t.cellsByRow[currentRowInd] = append(t.cellsByRow[currentRowInd], contents)
}

// SkipRow prints a span without having it contribute to the table calculation.
func (t *Table) SkipRow(contents Span) {
	t.cellsByRow = append(t.cellsByRow, []Span{contents})
}

func (t *Table) WriteTo(out io.Writer) error {
	if t.colSizes == nil {
		t.colSizes = t.Sizing.ColumnWidths()
	}

	for _, cells := range t.cellsByRow {
		currentPosition := 0
		for colInd, cell := range cells {
			colSize := t.colSizes[colInd]
			diff := colSize - cell.VisualLength()

			if err := cell.WriteTo(out); err != nil {
				return err
			}

			if diff > 0 {
				if err := writePadding(out, columnPadding, diff); err != nil {
					return err
				}
			}
			currentPosition += colSize
		}

		if _, err := fmt.Fprint(out, "\n"); err != nil {
			return err
		}
	}

	return nil
}

func (t *Table) VisualLength() int {
	if t.colSizes == nil {
		t.colSizes = t.Sizing.ColumnWidths()
	}

	res := 0
	for _, colSize := range t.colSizes {
		res += colSize
	}
	return res
}

// Text is a span that simply contains raw text.  It's a good starting point.
type Text string

func (t Text) VisualLength() int { return len(t) }
func (t Text) WriteTo(w io.Writer) error {
	_, err := w.Write([]byte(t))
	return err
}

// indented is a span that indents all lines by the given number of tabs.
type indented struct {
	Amount  int
	Content Span
}

func (i *indented) VisualLength() int { return i.Content.VisualLength() }
func (i *indented) WriteTo(w io.Writer) error {
	var out bytes.Buffer
	if err := i.Content.WriteTo(&out); err != nil {
		return err
	}

	lines := bytes.Split(out.Bytes(), []byte("\n"))
	for lineInd, line := range lines {
		if lineInd != 0 {
			if _, err := w.Write([]byte("\n")); err != nil {
				return err
			}
		}
		if len(line) == 0 {
			continue
		}

		if err := writePadding(w, indentPadding, i.Amount); err != nil {
			return err
		}
		if _, err := w.Write(line); err != nil {
			return err
		}
	}
	return nil
}

// Indented returns a span that indents all lines by the given number of tabs.
func Indented(amt int, content Span) Span {
	return &indented{Amount: amt, Content: content}
}

// fromWriter is a span that takes content from a function expecting a Writer.
type fromWriter struct {
	cache      []byte
	cacheError error
	run        func(io.Writer) error
}

func (f *fromWriter) VisualLength() int {
	if f.cache == nil {
		var buf bytes.Buffer
		if err := f.run(&buf); err != nil {
			f.cacheError = err
		}
		f.cache = buf.Bytes()
	}
	return len(f.cache)
}
func (f *fromWriter) WriteTo(w io.Writer) error {
	if f.cache != nil {
		if f.cacheError != nil {
			return f.cacheError
		}
		_, err := w.Write(f.cache)
		return err
	}
	return f.run(w)
}

// FromWriter returns a span that takes content from a function expecting a Writer.
func FromWriter(run func(io.Writer) error) Span {
	return &fromWriter{run: run}
}

// Decoration represents a terminal decoration.
type Decoration color.Color

// Containing returns a Span that has the given decoration applied.
func (d Decoration) Containing(contents Span) Span {
	return &decorated{
		Contents:   contents,
		Attributes: color.Color(d),
	}
}

// decorated is a span that has some terminal decoration applied.
type decorated struct {
	Contents   Span
	Attributes color.Color
}

func (d *decorated) VisualLength() int { return d.Contents.VisualLength() }
func (d *decorated) WriteTo(w io.Writer) error {
	oldOut := color.Output
	color.Output = w
	defer func() { color.Output = oldOut }()

	d.Attributes.Set()
	defer color.Unset()

	return d.Contents.WriteTo(w)
}

// SpanWriter is a span that contains multiple sub-spans.
type SpanWriter struct {
	contents []Span
}

func (m *SpanWriter) VisualLength() int {
	res := 0
	for _, span := range m.contents {
		res += span.VisualLength()
	}
	return res
}
func (m *SpanWriter) WriteTo(w io.Writer) error {
	for _, span := range m.contents {
		if err := span.WriteTo(w); err != nil {
			return err
		}
	}
	return nil
}

// Print adds a new span to this SpanWriter.
func (m *SpanWriter) Print(s Span) {
	m.contents = append(m.contents, s)
}

// lines is a span that adds some newlines, optionally followed by some content.
type lines struct {
	content      Span
	amountBefore int
}

func (l *lines) VisualLength() int {
	if l.content == nil {
		return 0
	}
	return l.content.VisualLength()
}
func (l *lines) WriteTo(w io.Writer) error {
	if err := writePadding(w, linesPadding, l.amountBefore); err != nil {
		return err
	}
	if l.content != nil {
		if err := l.content.WriteTo(w); err != nil {
			return err
		}
	}
	return nil
}

// Newlines returns a span just containing some newlines.
func Newlines(amt int) Span {
	return &lines{amountBefore: amt}
}

// Line returns a span that emits a newline, followed by the given content.
func Line(content Span) Span {
	return &lines{amountBefore: 1, content: content}
}

var (
	columnPadding = []byte("                                                                       ")
	indentPadding = []byte("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t")
	linesPadding  = []byte("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n")
)

// writePadding writes out padding of the given type in the given amount to the writer.
// Each byte in the padding buffer contributes 1 to the amount -- the padding being
// a buffer is just for efficiency.
func writePadding(out io.Writer, typ []byte, amt int) error {
	if amt <= len(typ) {
		_, err := out.Write(typ[:amt])
		return err
	}

	num := amt / len(typ)
	rem := amt % len(typ)
	for range num {
		if _, err := out.Write(typ); err != nil {
			return err
		}
	}

	if _, err := out.Write(typ[:rem]); err != nil {
		return err
	}
	return nil
}
