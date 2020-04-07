package gogo

const timestampTpl = `{{ $f := .Field }}{{ $r := .Rules }}
	{{ template "required" . }}

	{{ if or $r.Lt $r.Lte $r.Gt $r.Gte $r.LtNow $r.GtNow $r.Within $r.Const }}
		{{ if .Gogo.StdTime }}
			{{ if .Gogo.Nullable }}
				if ts := {{ accessor . }}; ts != nil {
			{{ else }}
				if ts := {{ accessor . }}; true {
			{{ end }}
		{{ else }}
			{{ if .Gogo.Nullable }}
				if t := {{ accessor . }}; t != nil {
					ts, err := types.TimestampFromProto(t)
					if err != nil { return {{ errCause . "err" "value is not a valid timestamp" }} }
			{{ else }}
				if t := {{ accessor . }}; true {
					ts, err := types.TimestampFromProto(&t)
					if err != nil { return {{ errCause . "err" "value is not a valid timestamp" }} }
			{{ end }}
		{{ end }}

					{{ template "timestampcmp" . }}
				}
	{{ end }}
`
