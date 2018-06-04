package main

import (
	pgs "github.com/lyft/protoc-gen-star"
	"github.com/lyft/protoc-gen-validate/templates"
)

const (
	validatorName = "validator"
	langParam     = "lang"
)

type Module struct {
	*pgs.ModuleBase
}

func Validator() Module { return Module{&pgs.ModuleBase{}} }

func (m Module) Name() string { return validatorName }

func (m Module) Execute(target pgs.Package, packages map[string]pgs.Package) []pgs.Artifact {
	lang := m.Parameters().Str(langParam)
	m.Assert(lang != "", "`lang` parameter must be set")
	tpls := templates.Template()[lang]
	m.Assert(tpls != nil, "could not find template for `lang`: ", lang)

	for _, f := range target.Files() {
		m.Push(f.Name().String())

		for _, msg := range f.AllMessages() {
			m.CheckRules(msg)
		}

		for _, tpl := range tpls {
			m.AddGeneratorTemplateFile(
				f.OutputPath().SetExt(".validate." + tpl.Name()).String(),
				tpl,
				f,
			)
		}

		m.Pop()
	}

	return m.Artifacts()
}

var _ pgs.Module = Module{}
