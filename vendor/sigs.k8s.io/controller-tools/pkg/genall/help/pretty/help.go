package pretty

import (
	"fmt"
	"io"

	"github.com/fatih/color"
	"sigs.k8s.io/controller-tools/pkg/genall/help"
)

var (
	headingStyle      = Decoration(*color.New(color.Bold, color.Underline))
	markerNameStyle   = Decoration(*color.New(color.Bold))
	fieldSummaryStyle = Decoration(*color.New(color.FgGreen, color.Italic))
	markerTargetStyle = Decoration(*color.New(color.Faint))
	fieldDetailStyle  = Decoration(*color.New(color.Italic, color.FgGreen))
	deprecatedStyle   = Decoration(*color.New(color.CrossedOut))
)

// MarkersSummary returns a condensed summary of help for the given markers.
func MarkersSummary(groupName string, markers []help.MarkerDoc) Span {
	out := new(SpanWriter)

	out.Print(Text("\n"))
	out.Print(headingStyle.Containing(Text(groupName)))
	out.Print(Text("\n\n"))

	table := &Table{Sizing: &TableCalculator{Padding: 2}}
	for _, marker := range markers {
		table.StartRow()
		table.Column(MarkerSyntaxHelp(marker))
		table.Column(markerTargetStyle.Containing(Text(marker.Target)))

		summary := new(SpanWriter)
		if marker.DeprecatedInFavorOf != nil && len(*marker.DeprecatedInFavorOf) > 0 {
			summary.Print(markerNameStyle.Containing(Text("(use ")))
			summary.Print(markerNameStyle.Containing(Text(*marker.DeprecatedInFavorOf)))
			summary.Print(markerNameStyle.Containing(Text(") ")))
		}
		summary.Print(Text(marker.Summary))
		table.Column(summary)

		table.EndRow()
	}
	out.Print(table)

	out.Print(Text("\n"))

	return out
}

// MarkersDetails returns detailed help for the given markers, including detailed field help.
func MarkersDetails(fullDetail bool, groupName string, markers []help.MarkerDoc) Span {
	out := new(SpanWriter)

	out.Print(Line(headingStyle.Containing(Text(groupName))))
	out.Print(Newlines(2))

	for _, marker := range markers {
		out.Print(Line(markerName(marker)))
		out.Print(Text(" "))
		out.Print(markerTargetStyle.Containing(Text(marker.Target)))

		summary := new(SpanWriter)
		if marker.DeprecatedInFavorOf != nil && len(*marker.DeprecatedInFavorOf) > 0 {
			summary.Print(markerNameStyle.Containing(Text("(use ")))
			summary.Print(markerNameStyle.Containing(Text(*marker.DeprecatedInFavorOf)))
			summary.Print(markerNameStyle.Containing(Text(") ")))
		}
		summary.Print(Text(marker.Summary))

		if !marker.AnonymousField() {
			out.Print(Indented(1, Line(summary)))
			if len(marker.Details) > 0 && fullDetail {
				out.Print(Indented(1, Line(Text(marker.Details))))
			}
		}

		switch {
		case marker.AnonymousField():
			out.Print(Indented(1, Line(fieldDetailStyle.Containing(FieldSyntaxHelp(marker.Fields[0])))))
			out.Print(Text("  "))
			out.Print(summary)
			if len(marker.Details) > 0 && fullDetail {
				out.Print(Indented(2, Line(Text(marker.Details))))
			}
			out.Print(Newlines(1))
		case !marker.Empty():
			out.Print(Newlines(1))
			if fullDetail {
				for _, arg := range marker.Fields {
					out.Print(Indented(1, Line(fieldDetailStyle.Containing(FieldSyntaxHelp(arg)))))
					out.Print(Indented(2, Line(Text(arg.Summary))))
					if len(arg.Details) > 0 && fullDetail {
						out.Print(Indented(2, Line(Text(arg.Details))))
						out.Print(Newlines(1))
					}
				}
				out.Print(Newlines(1))
			} else {
				table := &Table{Sizing: &TableCalculator{Padding: 2}}
				for _, arg := range marker.Fields {
					table.StartRow()
					table.Column(fieldDetailStyle.Containing(FieldSyntaxHelp(arg)))
					table.Column(Text(arg.Summary))
					table.EndRow()
				}

				out.Print(Indented(1, table))
			}
		default:
			out.Print(Newlines(1))
		}
	}

	return out
}

func FieldSyntaxHelp(arg help.FieldHelp) Span {
	return fieldSyntaxHelp(arg, "")
}

// fieldSyntaxHelp prints the syntax help for a particular marker argument.
func fieldSyntaxHelp(arg help.FieldHelp, sep string) Span {
	if arg.Optional {
		return FromWriter(func(out io.Writer) error {
			_, err := fmt.Fprintf(out, "[%s%s=<%s>]", sep, arg.Name, arg.TypeString())
			return err
		})
	}
	return FromWriter(func(out io.Writer) error {
		_, err := fmt.Fprintf(out, "%s%s=<%s>", sep, arg.Name, arg.TypeString())
		return err
	})
}

// markerName returns a span containing just the appropriately-formatted marker name.
func markerName(def help.MarkerDoc) Span {
	if def.DeprecatedInFavorOf != nil {
		return deprecatedStyle.Containing(Text("+" + def.Name))
	}
	return markerNameStyle.Containing(Text("+" + def.Name))
}

// MarkerSyntaxHelp assembles syntax help for a given marker.
func MarkerSyntaxHelp(def help.MarkerDoc) Span {
	out := new(SpanWriter)

	out.Print(markerName(def))

	if def.Empty() {
		return out
	}

	sep := ":"
	if def.AnonymousField() {
		sep = ""
	}

	fieldStyle := fieldSummaryStyle
	if def.DeprecatedInFavorOf != nil {
		fieldStyle = deprecatedStyle
	}

	for _, arg := range def.Fields {
		out.Print(fieldStyle.Containing(fieldSyntaxHelp(arg, sep)))
		sep = ","
	}

	return out
}
