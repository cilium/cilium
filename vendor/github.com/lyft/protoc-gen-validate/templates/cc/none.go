package tpl

const noneTpl = `// no validation rules for {{ .Field.Name.PGGUpperCamelCase }}
	{{- if .Index }}[{{ .Index }}]{{ end }}
	{{- if .OnKey }} (key){{ end }}`
