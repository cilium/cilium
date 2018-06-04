package tpl

const msgTpl = `
{{ if disabled . -}}
	{{ cmt "Validate is disabled for " .TypeName.Value ". This method will always return nil." }}
{{- else -}}
	{{ cmt "Validate checks the field values on " .TypeName.Value " with the rules defined in the proto definition for this message. If any rules are violated, an error is returned." }}
{{- end -}}
func (m {{ .TypeName.Pointer }}) Validate() error {
	{{ if disabled . -}}
		return nil
	{{ else -}}
		if m == nil { return nil }

		{{ range .NonOneOfFields }}
			{{ render (context .) }}
		{{ end }}

		{{ range .OneOfs }}
			switch m.{{ .Name.PGGUpperCamelCase }}.(type) {
				{{ range .Fields }}
					case {{ oneof . }}:
						{{ render (context .) }}
				{{ end }}
				{{ if required . }}
					default:
						return {{ errname .Message }}{
							Field: "{{ .Name.PGGUpperCamelCase }}",
							Reason: "value is required",
						}
				{{ end }}
			}
		{{ end }}

		return nil
	{{ end -}}
}

{{ if needs . "hostname" }}{{ template "hostname" . }}{{ end }}

{{ if needs . "email" }}{{ template "email" . }}{{ end }}

{{ cmt (errname .) " is the validation error returned by " .TypeName.Value ".Validate if the designated constraints aren't met." -}}
type {{ errname . }} struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e {{ errname . }}) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %s{{ .TypeName }}.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = {{ errname . }}{}

{{ range .Fields }}{{ with (context .) }}{{ $f := .Field }}
	{{ if has .Rules "In" }}{{ if .Rules.In }}
		var {{ lookup .Field "InLookup" }} = map[{{ inType .Field .Rules.In }}]struct{}{
			{{- range .Rules.In }}
				{{ inKey $f . }}: {},
			{{- end }}
		}
	{{ end }}{{ end }}

	{{ if has .Rules "NotIn" }}{{ if .Rules.NotIn }}
		var {{ lookup .Field "NotInLookup" }} = map[{{ inType .Field .Rules.In }}]struct{}{
			{{- range .Rules.NotIn }}
				{{ inKey $f . }}: {},
			{{- end }}
		}
	{{ end }}{{ end }}

	{{ if has .Rules "Pattern"}}{{ if .Rules.Pattern }}
		var {{ lookup .Field "Pattern" }} = regexp.MustCompile({{ lit .Rules.GetPattern }})
	{{ end }}{{ end }}

	{{ if has .Rules "Items"}}{{ if .Rules.Items }}
	{{ if has .Rules.Items.GetString_ "Pattern" }} {{ if .Rules.Items.GetString_.Pattern }}
		var {{ lookup .Field "Pattern" }} = regexp.MustCompile({{ lit .Rules.Items.GetString_.GetPattern }})
	{{ end }}{{ end }}
	{{ end }}{{ end }}

	{{ if has .Rules "Keys"}}{{ if .Rules.Keys }}
	{{ if has .Rules.Keys.GetString_ "Pattern" }} {{ if .Rules.Keys.GetString_.Pattern }}
		var {{ lookup .Field "Pattern" }} = regexp.MustCompile({{ lit .Rules.Keys.GetString_.GetPattern }})
	{{ end }}{{ end }}
	{{ end }}{{ end }}

	{{ if has .Rules "Values"}}{{ if .Rules.Values }}
	{{ if has .Rules.Values.GetString_ "Pattern" }} {{ if .Rules.Values.GetString_.Pattern }}
		var {{ lookup .Field "Pattern" }} = regexp.MustCompile({{ lit .Rules.Values.GetString_.GetPattern }})
	{{ end }}{{ end }}
	{{ end }}{{ end }}

{{ end }}{{ end }}
`
