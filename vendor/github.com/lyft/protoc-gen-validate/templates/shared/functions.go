package shared

import "text/template"

func RegisterFunctions(tpl *template.Template) {
	tpl.Funcs(map[string]interface{}{
		"disabled": Disabled,
		"required": RequiredOneOf,
		"context":  rulesContext,
		"render":   Render(tpl),
		"has":      Has,
		"needs":    Needs,
	})
}
