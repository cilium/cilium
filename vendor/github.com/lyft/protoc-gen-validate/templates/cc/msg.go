package tpl

const declTpl = `
extern bool Validate(const {{ class . }}& m, pgv::ValidationMsg* err);
`

const msgTpl = `
{{ if disabled . -}}
	{{ cmt "Validate is disabled for " (class .) ". This method will always return true." }}
{{- else -}}
	{{ cmt "Validate checks the field values on " (class .) " with the rules defined in the proto definition for this message. If any rules are violated, the return value is false and an error message is written to the input string argument." }}
{{- end -}}

{{ range .Fields }}{{ with (context .) }}{{ $f := .Field }}
	{{ if has .Rules "In" }}{{ if .Rules.In }}
	const std::set<{{ inType .Field .Rules.In }}> {{ lookup .Field "InLookup" }} = {
			{{- range .Rules.In }}
				{{ inKey $f . }},
			{{- end }}
		};
	{{ end }}{{ end }}

	{{ if has .Rules "NotIn" }}{{ if .Rules.NotIn }}
	const std::set<{{ inType .Field .Rules.NotIn }}> {{ lookup .Field "NotInLookup" }} = {
			{{- range .Rules.NotIn }}
				{{ inKey $f . }},
			{{- end }}
		};
	{{ end }}{{ end }}

	{{ if has .Rules "Pattern"}}{{ if .Rules.Pattern }}
	{{/* TODO(akonradi) implement pattern matching
		var {{ lookup .Field "Pattern" }} = regexp.MustCompile({{ lit .Rules.GetPattern }})
	*/}}
	{{ end }}{{ end }}

{{ end }}{{ end }}

bool Validate(const {{ class . }}& m, pgv::ValidationMsg* err) {
	(void)m;
	(void)err;
{{- if disabled . }}
	return true;
{{ else -}}
		{{ range .NonOneOfFields }}
			{{- render (context .) -}}
		{{ end -}}
		{{ range .OneOfs }}
			switch (m.{{ .Name }}_case()) {
				{{ range .Fields -}}
					case {{ oneof . }}:
						{{ render (context .) }}
						break;
				{{ end -}}
					default:
				{{- if required . }}
						*err = "field: " {{ .Name | quote | lit }} ", reason: is required";
						return false;
				{{ end }}
					break;
			}
		{{ end }}
	return true;
{{ end -}}
}

{{/* TODO(akonradi) implement hostname matching
{{ if needs . "hostname" }}{{ template "hostname" . }}{{ end }}

{{ if needs . "email" }}{{ template "email" . }}{{ end }}
*/}}

`
