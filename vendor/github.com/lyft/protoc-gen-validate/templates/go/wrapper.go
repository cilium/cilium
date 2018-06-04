package tpl

const wrapperTpl = `
	{{ $f := .Field }}{{ $r := .Rules }}

	if wrapper := {{ accessor . }}; wrapper != nil {
		{{ render (unwrap . "wrapper") }}
	}
`
