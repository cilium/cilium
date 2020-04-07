package gogo

const messageTpl = `
	{{ $f := .Field }}{{ $r := .Rules }}
	{{ template "required" . }}

	{{ if $r.GetSkip }}
		// skipping validation for {{ $f.Name }}
	{{ else }}
	{
		tmp := {{ accessor . }}
		{{ if .Gogo.Nullable }}
		if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {
		{{ else }}
		if v, ok := interface{}(&tmp).(interface{ Validate() error }); ok {
		{{ end }}
			if err := v.Validate(); err != nil {
				return {{ errCause . "err" "embedded message failed validation" }}
			}
		}
	}
	{{ end }}
`
