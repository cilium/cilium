package gogo

const durationTpl = `{{ $f := .Field }}{{ $r := .Rules }}
	{{ template "required" . }}

	{{ if or $r.In $r.NotIn $r.Lt $r.Lte $r.Gt $r.Gte $r.Const }}
		{{ if .Gogo.StdDuration }}
			{{ if .Gogo.Nullable }}
				if d := {{ accessor . }}; d != nil {
					dur := *d
			{{ else }}
				if true {
					dur := {{ accessor . }}
			{{ end }}
		{{ else }}
			{{ if .Gogo.Nullable }}
				if d := {{ accessor . }}; d != nil {
					dur, err := types.DurationFromProto(d)
					if err != nil { return {{ errCause . "err" "value is not a valid duration" }} }
			{{ else }}
				if d := {{ accessor . }}; true {
					dur, err := types.DurationFromProto(&d)
					if err != nil { return {{ errCause . "err" "value is not a valid duration" }} }
			{{ end }}
		{{ end }}

					{{ template "durationcmp" . }}
				}
	{{ end }}
`
