package tpl

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"text/template"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/timestamp"
	pgs "github.com/lyft/protoc-gen-star"
	"github.com/lyft/protoc-gen-validate/templates/shared"
)

func RegisterModule(tpl *template.Template) {
	tpl.Funcs(map[string]interface{}{
		"cmt":           pgs.C80,
		"class":         className,
		"package":       packageName,
		"accessor":      accessor,
		"hasAccessor":   hasAccessor,
		"ctype":         cType,
		"weakCheckMsgs": weakCheckMsgs,
		"err":           err,
		"errCause":      errCause,
		"errIdx":        errIdx,
		"errIdxCause":   errIdxCause,
		"lookup":        lookup,
		"lit":           lit,
		"isBytes":       isBytes,
		"byteStr":       byteStr,
		"oneof":         oneofTypeName,
		"quote":         quote,
		"inType":        inType,
		"inKey":         inKey,
		"durLit":        durLit,
		"durStr":        durStr,
		"durGt":         durGt,
		"tsLit":         tsLit,
		"tsGt":          tsGt,
		"tsStr":         tsStr,
		"unwrap":        unwrap,
		"unimplemented": failUnimplemented,
	})
	template.Must(tpl.Parse(moduleFileTpl))
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

func RegisterHeader(tpl *template.Template) {
	tpl.Funcs(map[string]interface{}{
		"class":         className,
		"upper":         strings.ToUpper,
	})

	template.Must(tpl.Parse(headerFileTpl))
	template.Must(tpl.New("decl").Parse(declTpl))
}

func methodName(name interface{}) string {
	nameStr := fmt.Sprintf("%s", name)
	switch nameStr {
	case "const":
		return "const_"
	case "inline":
		return "inline_"
	default:
		return nameStr
	}
}

func accessor(ctx shared.RuleContext) string {
	if ctx.AccessorOverride != "" {
		return ctx.AccessorOverride
	}

	return fmt.Sprintf(
		"m.%s()",
		methodName(ctx.Field.Name()))
}

func hasAccessor(ctx shared.RuleContext) string {
	if ctx.AccessorOverride != "" {
		return "true"
	}

	return fmt.Sprintf(
		"m.has_%s()",
		methodName(ctx.Field.Name()))
}

func className(msg pgs.Message) string {
	return packageName(msg) + "::" + string(msg.TypeName())
}

func packageName(msg pgs.Message) string {
	return strings.Join(msg.Package().ProtoName().Split(), "::")
}

func quote(s interface {
	String() string
}) string {
	return strconv.Quote(s.String())
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
	errName := fmt.Sprintf("%sValidationError", f.Message().Name())

	output := []string{
		"{",
		`std::ostringstream msg("invalid ");`,
	}

	if ctx.OnKey {
		output = append(output, `msg << "key for ";`)
	}
	output = append(output,
		fmt.Sprintf(`msg << %q << "." << %s;`,
			errName, lit(f.Name().PGGUpperCamelCase().String())))

	if idx != "" {
		output = append(output, fmt.Sprintf(`msg << "[" << %s << "]";`, lit(idx)))
	} else if ctx.Index != "" {
		output = append(output, fmt.Sprintf(`msg << "[" << %s << "]";`, lit(ctx.Index)))
	}

	output = append(output, fmt.Sprintf(`msg << ": " << %s;`, lit(fmt.Sprintf("%q", reason))))

	if cause != "nil" && cause != "" {
		output = append(output, fmt.Sprintf(`msg << " | caused by " << %s;`, cause))
	}

	output = append(output, "*err = msg.str();",
		"return false;",
		"}")
	return strings.Join(output, "\n")
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
		switch reflect.TypeOf(x).Elem().Kind() {
		case reflect.Uint8:
			for i, l := 0, val.Len(); i < l; i++ {
				els[i] = fmt.Sprintf("\\x%x", val.Index(i).Interface())
			}
			return fmt.Sprintf("\"%s\"", strings.Join(els, ""))
		default:
			panic(fmt.Sprintf("don't know how to format literals of type %v", val.Kind()))
		}
	case reflect.Float32:
		return fmt.Sprintf("%fF", x)
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
	return pgs.TypeName(fmt.Sprintf("%s::%sCase::k%s",
		className(f.Message()),
		f.OneOf().Name().PGGUpperCamelCase(),
		f.Name().PGGUpperCamelCase(),
	))
}

func inType(f pgs.Field, x interface{}) string {
	switch f.Type().ProtoType() {
	case pgs.BytesT:
		return "string"
	case pgs.MessageT:
		switch x.(type) {
		case []string:
			return "string"
		case []*duration.Duration:
			return "pgv::protobuf_wkt::Duration"
		default:
			return className(f.Type().Element().Embed())
		}
	default:
		return cType(f.Type())
	}
}

func cType(t pgs.FieldType) string {
	if t.IsEmbed() {
		return className(t.Embed())
	}
	if t.IsRepeated(){
		if t.ProtoType() == pgs.MessageT {
			return className(t.Element().Embed())
		}
		// Strip the leading []
		return cTypeOfString(t.Name().String()[2:])
	}

	return cTypeOfString(t.Name().String())
}

// Compute unique C++ types that correspond to all message fields in a
// compilation unit that need to be weak (i.e. not already defined). Used to
// generate weak default definitions for CheckMessage.
func weakCheckMsgs(msgs []pgs.Message) []string {
	already_defined := map[string]bool{}
	// First compute the C++ type names for things we're going to provide an explicit
	// CheckMessage() with Validate(..) body in this file. We can't define the
	// same CheckMessage() signature twice in a compilation unit, even if one of
	// them is weak.
	for _, msg := range msgs {
		already_defined[className(msg)] = true
	}
	// Compute the set of C++ type names we need weak definitions for.
	ctype_map := map[string]bool{}
	for _, msg := range msgs {
		if disabled, _ := shared.Disabled(msg); disabled {
			continue
		}
		for _, f := range msg.Fields() {
			ctype := cType(f.Type())
			if already_defined[ctype] {
				continue
			}
			if f.Type().IsEmbed() || (f.Type().IsRepeated() && f.Type().Element().IsEmbed()) {
				ctype_map[ctype] = true
			}
		}
	}
	// Convert to array.
	ctypes := make([]string, 0, len(ctype_map))
	for ctype := range ctype_map {
		ctypes = append(ctypes, ctype)
	}
	return ctypes
}

func cTypeOfString(s string) string {
	switch s {
	case "float32":
		return "float"
	case "float64":
		return "double"
	case "int32":
		return "int32_t"
	case "int64":
		return "int64_t"
	case "uint32":
		return "uint32_t"
	case "uint64":
		return "uint64_t"
	case "[]byte":
		return "string"
	default:
		return s
	}
}

func inKey(f pgs.Field, x interface{}) string {
	switch f.Type().ProtoType() {
	case pgs.BytesT:
		return byteStr(x.([]byte))
	case pgs.MessageT:
		switch x := x.(type) {
		case *duration.Duration:
			return durLit(x)
		default:
			return lit(x)
		}
	case pgs.EnumT:
		return fmt.Sprintf("%s(%d)", cType(f.Type()), x.(int32))
	default:
		return lit(x)
	}
}

func durLit(dur *duration.Duration) string {
	return fmt.Sprintf(
		"pgv::protobuf::util::TimeUtil::SecondsToDuration(%d) + pgv::protobuf::util::TimeUtil::NanosecondsToDuration(%d)",
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

	return !bt.Before(at)
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

	ctx.AccessorOverride = fmt.Sprintf("%s.%s()", name,
		ctx.Field.Type().Embed().Fields()[0].Name())

	return ctx, nil
}

func failUnimplemented() string {
	return "throw pgv::UnimplementedException();"
}
