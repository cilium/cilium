package tpl

const enumTpl = `
		{{ $f := .Field }}{{ $r := .Rules }}
		{{ template "const" . }}
		{{ template "in" . }}

		{{ if $r.GetDefinedOnly }}
			if (!{{ $f.Type.Name.Element }}_IsValid({{ accessor . }})) {
				{{ err . "value must be one of the defined enum values" }}
			}
		{{ end }}
`
