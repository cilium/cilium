package tpl

const messageTpl = `
	{{ $f := .Field }}{{ $r := .Rules }}
	{{ template "required" . }}

	{{ if $r.GetSkip }}
		// skipping validation for {{ $f.Name }}
	{{ else }}
		if v, ok := interface{}({{ accessor . }}).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return {{ errCause . "err" "embedded message failed validation" }}
			}
		}
	{{ end }}
`

const requiredTpl = `
	{{ if .Rules.GetRequired }}
		if {{ accessor . }} == nil {
			return {{ err . "value is required" }}
		}
	{{ end }}
`
