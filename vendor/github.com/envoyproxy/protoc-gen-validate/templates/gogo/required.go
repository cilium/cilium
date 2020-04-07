package gogo

const requiredTpl = `
	{{ if .Rules.GetRequired }}
		{{ if .Gogo.Nullable }}
			if {{ accessor . }} == nil {
				return {{ err . "value is required" }}
			}
		{{ end }}
	{{ end }}
`
