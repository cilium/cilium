package shared

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/golang/protobuf/proto"
	"github.com/lyft/protoc-gen-star"
	"github.com/lyft/protoc-gen-validate/validate"
)

type RuleContext struct {
	Field pgs.Field
	Rules proto.Message

	Typ        string
	WrapperTyp string

	OnKey            bool
	Index            string
	AccessorOverride string
}

func rulesContext(f pgs.Field) (out RuleContext, err error) {
	out.Field = f

	var rules validate.FieldRules
	if _, err = f.Extension(validate.E_Rules, &rules); err != nil {
		return
	}

	var wrapped bool
	if out.Typ, out.Rules, wrapped = resolveRules(f.Type(), &rules); wrapped {
		out.WrapperTyp = out.Typ
		out.Typ = "wrapper"
	}

	if out.Typ == "error" {
		err = fmt.Errorf("unknown rule type (%T)", rules.Type)
	}

	return
}

func (ctx RuleContext) Key(name, idx string) (out RuleContext, err error) {
	rules, ok := ctx.Rules.(*validate.MapRules)
	if !ok {
		err = fmt.Errorf("cannot get Key RuleContext from %T", ctx.Field)
		return
	}

	out.Field = ctx.Field
	out.AccessorOverride = name
	out.Index = idx

	out.Typ, out.Rules, _ = resolveRules(ctx.Field.Type().Key(), rules.GetKeys())

	if out.Typ == "error" {
		err = fmt.Errorf("unknown rule type (%T)", rules)
	}

	return
}

func (ctx RuleContext) Elem(name, idx string) (out RuleContext, err error) {
	out.Field = ctx.Field
	out.AccessorOverride = name
	out.Index = idx

	var rules *validate.FieldRules
	switch r := ctx.Rules.(type) {
	case *validate.MapRules:
		rules = r.GetValues()
	case *validate.RepeatedRules:
		rules = r.GetItems()
	default:
		err = fmt.Errorf("cannot get Elem RuleContext from %T", ctx.Field)
		return
	}

	var wrapped bool
	if out.Typ, out.Rules, wrapped = resolveRules(ctx.Field.Type().Element(), rules); wrapped {
		out.WrapperTyp = out.Typ
		out.Typ = "wrapper"
	}

	if out.Typ == "error" {
		err = fmt.Errorf("unknown rule type (%T)", rules)
	}

	return
}

func (ctx RuleContext) Unwrap(name string) (out RuleContext, err error) {
	if ctx.Typ != "wrapper" {
		err = fmt.Errorf("cannot unwrap non-wrapper type %q", ctx.Typ)
		return
	}

	return RuleContext{
		Field:            ctx.Field,
		Rules:            ctx.Rules,
		Typ:              ctx.WrapperTyp,
		AccessorOverride: name,
	}, nil
}

func Render(tpl *template.Template) func(ctx RuleContext) (string, error) {
	return func(ctx RuleContext) (string, error) {
		var b bytes.Buffer
		err := tpl.ExecuteTemplate(&b, ctx.Typ, ctx)
		return b.String(), err
	}
}

type ruleTarget interface {
	IsEmbed() bool
	Name() pgs.TypeName
}

func resolveRules(typ ruleTarget, rules *validate.FieldRules) (string, proto.Message, bool) {
	switch r := rules.GetType().(type) {
	case *validate.FieldRules_Float:
		return "float", r.Float, typ.IsEmbed()
	case *validate.FieldRules_Double:
		return "double", r.Double, typ.IsEmbed()
	case *validate.FieldRules_Int32:
		return "int32", r.Int32, typ.IsEmbed()
	case *validate.FieldRules_Int64:
		return "int64", r.Int64, typ.IsEmbed()
	case *validate.FieldRules_Uint32:
		return "uint32", r.Uint32, typ.IsEmbed()
	case *validate.FieldRules_Uint64:
		return "uint64", r.Uint64, typ.IsEmbed()
	case *validate.FieldRules_Sint32:
		return "sint32", r.Sint32, false
	case *validate.FieldRules_Sint64:
		return "sint64", r.Sint64, false
	case *validate.FieldRules_Fixed32:
		return "fixed32", r.Fixed32, false
	case *validate.FieldRules_Fixed64:
		return "fixed64", r.Fixed64, false
	case *validate.FieldRules_Sfixed32:
		return "sfixed32", r.Sfixed32, false
	case *validate.FieldRules_Sfixed64:
		return "sfixed64", r.Sfixed64, false
	case *validate.FieldRules_Bool:
		return "bool", r.Bool, typ.IsEmbed()
	case *validate.FieldRules_String_:
		return "string", r.String_, typ.IsEmbed()
	case *validate.FieldRules_Bytes:
		return "bytes", r.Bytes, typ.IsEmbed()
	case *validate.FieldRules_Enum:
		return "enum", r.Enum, false
	case *validate.FieldRules_Message:
		return "message", r.Message, false
	case *validate.FieldRules_Repeated:
		return "repeated", r.Repeated, false
	case *validate.FieldRules_Map:
		return "map", r.Map, false
	case *validate.FieldRules_Any:
		return "any", r.Any, false
	case *validate.FieldRules_Duration:
		return "duration", r.Duration, false
	case *validate.FieldRules_Timestamp:
		return "timestamp", r.Timestamp, false
	case nil:
		if ft, ok := typ.(pgs.FieldType); ok && ft.IsRepeated() {
			return "repeated", &validate.RepeatedRules{}, false
		} else if typ.IsEmbed() {
			return "message", &validate.MessageRules{}, false
		}
		return "none", nil, false
	default:
		return "error", nil, false
	}
}
