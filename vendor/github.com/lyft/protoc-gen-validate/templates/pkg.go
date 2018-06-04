package templates

import (
	"text/template"

	cctpl "github.com/lyft/protoc-gen-validate/templates/cc"
	gotpl "github.com/lyft/protoc-gen-validate/templates/go"
	"github.com/lyft/protoc-gen-validate/templates/shared"
)

func makeTemplate(lang string, register_fn func(*template.Template)) *template.Template {
	tpl := template.New(lang)
	shared.RegisterFunctions(tpl)
	register_fn(tpl)
	return tpl
}

func Template() map[string][]*template.Template {
	return map[string][]*template.Template{
		"cc": {makeTemplate("h", cctpl.RegisterHeader), makeTemplate("cc", cctpl.RegisterModule)},
		"go": {makeTemplate("go", gotpl.Register)},
	}
}
