package tpl

import (
	"fmt"
	"reflect"
	"strings"
	"text/template"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/timestamp"
	pgs "github.com/lyft/protoc-gen-star"
	"github.com/lyft/protoc-gen-validate/templates/shared"
)

func Register(tpl *template.Template) {
	tpl.Funcs(map[string]interface{}{
		"cmt":         pgs.C80,
		"accessor":    accessor,
		"errname":     errName,
		"err":         err,
		"errCause":    errCause,
		"errIdx":      errIdx,
		"errIdxCause": errIdxCause,
		"lookup":      lookup,
		"lit":         lit,
		"isBytes":     isBytes,
		"byteStr":     byteStr,
		"oneof":       oneofTypeName,
		"inType":      inType,
		"inKey":       inKey,
		"durLit":      durLit,
		"durStr":      durStr,
		"durGt":       durGt,
		"tsLit":       tsLit,
		"tsGt":        tsGt,
		"tsStr":       tsStr,
		"unwrap":      unwrap,
	})

	template.Must(tpl.Parse(fileTpl))
	template.Must(tpl.New("msg").Parse(msgTpl))
	template.Must(tpl.New("const").Parse(constTpl))
	template.Must(tpl.New("ltgt").Parse(ltgtTpl))
	template.Must(tpl.New("in").Parse(inTpl))
	template.Must(tpl.New("required").Parse(requiredTpl))

	template.Must(tpl.New("none").Parse(noneTpl))
	template.Must(tpl.New("float").Parse(numTpl))
	template.Must(tpl.New("double").Parse(numTpl))
	template.Must(tpl.New("int32").Parse(numTpl))
	template.Must(tpl.New("int64").Parse(numTpl))
	template.Must(tpl.New("uint32").Parse(numTpl))
	template.Must(tpl.New("uint64").Parse(numTpl))
	template.Must(tpl.New("sint32").Parse(numTpl))
	template.Must(tpl.New("sint64").Parse(numTpl))
	template.Must(tpl.New("fixed32").Parse(numTpl))
	template.Must(tpl.New("fixed64").Parse(numTpl))
	template.Must(tpl.New("sfixed32").Parse(numTpl))
	template.Must(tpl.New("sfixed64").Parse(numTpl))

	template.Must(tpl.New("bool").Parse(constTpl))
	template.Must(tpl.New("string").Parse(strTpl))
	template.Must(tpl.New("bytes").Parse(bytesTpl))

	template.Must(tpl.New("email").Parse(emailTpl))
	template.Must(tpl.New("hostname").Parse(hostTpl))

	template.Must(tpl.New("enum").Parse(enumTpl))
	template.Must(tpl.New("message").Parse(messageTpl))
	template.Must(tpl.New("repeated").Parse(repTpl))
	template.Must(tpl.New("map").Parse(mapTpl))

	template.Must(tpl.New("any").Parse(anyTpl))
	template.Must(tpl.New("duration").Parse(durationTpl))
	template.Must(tpl.New("timestamp").Parse(timestampTpl))

	template.Must(tpl.New("wrapper").Parse(wrapperTpl))
}

func accessor(ctx shared.RuleContext) string {
	if ctx.AccessorOverride != "" {
		return ctx.AccessorOverride
	}

	return fmt.Sprintf(
		"m.Get%s()",
		ctx.Field.Name().PGGUpperCamelCase())
}

func errName(m pgs.Message) pgs.Name {
	return pgs.Name(fmt.Sprintf(
		"%sValidationError",
		m.TypeName()))
}

func err(ctx shared.RuleContext, reason ...interface{}) string {
	return errIdxCause(ctx, "", "nil", reason...)
}

func errCause(ctx shared.RuleContext, cause string, reason ...interface{}) string {
	return errIdxCause(ctx, "", cause, reason...)
}

func errIdx(ctx shared.RuleContext, idx string, reason ...interface{}) string {
	return errIdxCause(ctx, idx, "nil", reason...)
}

func errIdxCause(ctx shared.RuleContext, idx, cause string, reason ...interface{}) string {
	f := ctx.Field

	var fld string
	if idx != "" {
		fld = fmt.Sprintf(`fmt.Sprintf("%s[%%v]", %s)`, f.Name().PGGUpperCamelCase().String(), idx)
	} else if ctx.Index != "" {
		fld = fmt.Sprintf(`fmt.Sprintf("%s[%%v]", %s)`, f.Name().PGGUpperCamelCase().String(), ctx.Index)
	} else {
		fld = fmt.Sprintf("%q", f.Name().PGGUpperCamelCase().String())
	}

	causeFld := ""
	if cause != "nil" && cause != "" {
		causeFld = fmt.Sprintf("Cause: %s,", cause)
	}

	keyFld := ""
	if ctx.OnKey {
		keyFld = "Key: true,"
	}

	return fmt.Sprintf(`%s{
		Field: %s,
		Reason: %q,
		%s%s
	}`,
		errName(f.Message()),
		fld,
		fmt.Sprint(reason...),
		causeFld,
		keyFld)
}

func lookup(f pgs.Field, name string) string {
	return fmt.Sprintf(
		"_%s_%s_%s",
		f.Message().Name().PGGUpperCamelCase(),
		f.Name().PGGUpperCamelCase(),
		name,
	)
}

func lit(x interface{}) string {
	val := reflect.ValueOf(x)

	if val.Kind() == reflect.Interface {
		val = val.Elem()
	}

	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	switch val.Kind() {
	case reflect.String:
		return fmt.Sprintf("%q", x)
	case reflect.Uint8:
		return fmt.Sprintf("0x%X", x)
	case reflect.Slice:
		els := make([]string, val.Len())
		for i, l := 0, val.Len(); i < l; i++ {
			els[i] = lit(val.Index(i).Interface())
		}
		return fmt.Sprintf("%T{%s}", val.Interface(), strings.Join(els, ", "))
	default:
		return fmt.Sprint(x)
	}
}

func isBytes(f interface {
	ProtoType() pgs.ProtoType
}) bool {
	return f.ProtoType() == pgs.BytesT
}

func byteStr(x []byte) string {
	elms := make([]string, len(x))
	for i, b := range x {
		elms[i] = fmt.Sprintf(`\x%X`, b)
	}

	return fmt.Sprintf(`"%s"`, strings.Join(elms, ""))
}

func oneofTypeName(f pgs.Field) pgs.TypeName {
	name := pgs.TypeName(fmt.Sprintf("%s_%s",
		f.Message().TypeName().Value().String(),
		f.Name().PGGUpperCamelCase(),
	))

	for _, enum := range f.Message().Enums() {
		if name == enum.TypeName() {
			name += "_"
			break
		}
	}

	for _, msg := range f.Message().Messages() {
		if name == msg.TypeName() {
			name += "_"
			break
		}
	}

	return name.Pointer()
}

func inType(f pgs.Field, x interface{}) string {
	switch f.Type().ProtoType() {
	case pgs.BytesT:
		return "string"
	case pgs.MessageT:
		switch x.(type) {
		case []*duration.Duration:
			return "time.Duration"
		default:
			return pgs.TypeName(fmt.Sprintf("%T", x)).Element().String()
		}
	default:
		return f.Type().Name().String()
	}
}

func inKey(f pgs.Field, x interface{}) string {
	switch f.Type().ProtoType() {
	case pgs.BytesT:
		return byteStr(x.([]byte))
	case pgs.MessageT:
		switch x := x.(type) {
		case *duration.Duration:
			dur, _ := ptypes.Duration(x)
			return lit(int64(dur))
		default:
			return lit(x)
		}
	default:
		return lit(x)
	}
}

func durLit(dur *duration.Duration) string {
	return fmt.Sprintf(
		"time.Duration(%d * time.Second + %d * time.Nanosecond)",
		dur.GetSeconds(), dur.GetNanos())
}

func durStr(dur *duration.Duration) string {
	d, _ := ptypes.Duration(dur)
	return d.String()
}

func durGt(a, b *duration.Duration) bool {
	ad, _ := ptypes.Duration(a)
	bd, _ := ptypes.Duration(b)

	return ad > bd
}

func tsLit(ts *timestamp.Timestamp) string {
	return fmt.Sprintf(
		"time.Unix(%d, %d)",
		ts.GetSeconds(), ts.GetNanos(),
	)
}

func tsGt(a, b *timestamp.Timestamp) bool {
	at, _ := ptypes.Timestamp(a)
	bt, _ := ptypes.Timestamp(b)

	return bt.Before(at)
}

func tsStr(ts *timestamp.Timestamp) string {
	t, _ := ptypes.Timestamp(ts)
	return t.String()
}

func unwrap(ctx shared.RuleContext, name string) (shared.RuleContext, error) {
	ctx, err := ctx.Unwrap("wrapper")
	if err != nil {
		return ctx, err
	}

	ctx.AccessorOverride = fmt.Sprintf("%s.Get%s()", name,
		ctx.Field.Type().Embed().Fields()[0].Name().PGGUpperCamelCase())

	return ctx, nil
}
