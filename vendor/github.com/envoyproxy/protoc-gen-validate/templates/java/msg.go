package java

const msgTpl = `
	/**
	 * Validates {@code {{ simpleName . }}} protobuf objects.
	 */
	public static class {{ simpleName . }}Validator implements io.envoyproxy.pgv.ValidatorImpl<{{ qualifiedName . }}> {
		{{- template "msgInner" . -}}
	}
`

const msgInnerTpl = `
	{{- range .NonOneOfFields }}
		{{ renderConstants (context .) }}
	{{ end }}
	{{ range .OneOfs }}
		{{ template "oneOfConst" . }}
	{{ end }}

	public void assertValid({{ qualifiedName . }} proto, io.envoyproxy.pgv.ValidatorIndex index) throws io.envoyproxy.pgv.ValidationException {
	{{ if disabled . }}
		// Validate is disabled for {{ simpleName . }}
		return;
	{{- else -}}
	{{ range .NonOneOfFields -}}
		{{ render (context .) }}
	{{ end -}}
	{{ range .OneOfs }}
		{{ template "oneOf" . }}
	{{- end -}}
	{{- end }}
	}
`
