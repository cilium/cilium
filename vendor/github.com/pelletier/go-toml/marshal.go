package toml

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	tagFieldName    = "toml"
	tagFieldComment = "comment"
	tagCommented    = "commented"
	tagMultiline    = "multiline"
	tagDefault      = "default"
)

type tomlOpts struct {
	name         string
	comment      string
	commented    bool
	multiline    bool
	include      bool
	omitempty    bool
	defaultValue string
}

type encOpts struct {
	quoteMapKeys            bool
	arraysOneElementPerLine bool
}

var encOptsDefaults = encOpts{
	quoteMapKeys: false,
}

type annotation struct {
	tag          string
	comment      string
	commented    string
	multiline    string
	defaultValue string
}

var annotationDefault = annotation{
	tag:          tagFieldName,
	comment:      tagFieldComment,
	commented:    tagCommented,
	multiline:    tagMultiline,
	defaultValue: tagDefault,
}

type marshalOrder int

// Orders the Encoder can write the fields to the output stream.
const (
	// Sort fields alphabetically.
	OrderAlphabetical marshalOrder = iota + 1
	// Preserve the order the fields are encountered. For example, the order of fields in
	// a struct.
	OrderPreserve
)

var timeType = reflect.TypeOf(time.Time{})
var marshalerType = reflect.TypeOf(new(Marshaler)).Elem()
var localDateType = reflect.TypeOf(LocalDate{})
var localTimeType = reflect.TypeOf(LocalTime{})
var localDateTimeType = reflect.TypeOf(LocalDateTime{})

// Check if the given marshal type maps to a Tree primitive
func isPrimitive(mtype reflect.Type) bool {
	switch mtype.Kind() {
	case reflect.Ptr:
		return isPrimitive(mtype.Elem())
	case reflect.Bool:
		return true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	case reflect.Float32, reflect.Float64:
		return true
	case reflect.String:
		return true
	case reflect.Struct:
		return mtype == timeType || mtype == localDateType || mtype == localDateTimeType || mtype == localTimeType || isCustomMarshaler(mtype)
	default:
		return false
	}
}

// Check if the given marshal type maps to a Tree slice or array
func isTreeSequence(mtype reflect.Type) bool {
	switch mtype.Kind() {
	case reflect.Ptr:
		return isTreeSequence(mtype.Elem())
	case reflect.Slice, reflect.Array:
		return isTree(mtype.Elem())
	default:
		return false
	}
}

// Check if the given marshal type maps to a non-Tree slice or array
func isOtherSequence(mtype reflect.Type) bool {
	switch mtype.Kind() {
	case reflect.Ptr:
		return isOtherSequence(mtype.Elem())
	case reflect.Slice, reflect.Array:
		return !isTreeSequence(mtype)
	default:
		return false
	}
}

// Check if the given marshal type maps to a Tree
func isTree(mtype reflect.Type) bool {
	switch mtype.Kind() {
	case reflect.Ptr:
		return isTree(mtype.Elem())
	case reflect.Map:
		return true
	case reflect.Struct:
		return !isPrimitive(mtype)
	default:
		return false
	}
}

func isCustomMarshaler(mtype reflect.Type) bool {
	return mtype.Implements(marshalerType)
}

func callCustomMarshaler(mval reflect.Value) ([]byte, error) {
	return mval.Interface().(Marshaler).MarshalTOML()
}

// Marshaler is the interface implemented by types that
// can marshal themselves into valid TOML.
type Marshaler interface {
	MarshalTOML() ([]byte, error)
}

/*
Marshal returns the TOML encoding of v.  Behavior is similar to the Go json
encoder, except that there is no concept of a Marshaler interface or MarshalTOML
function for sub-structs, and currently only definite types can be marshaled
(i.e. no `interface{}`).

The following struct annotations are supported:

  toml:"Field"      Overrides the field's name to output.
  omitempty         When set, empty values and groups are not emitted.
  comment:"comment" Emits a # comment on the same line. This supports new lines.
  commented:"true"  Emits the value as commented.

Note that pointers are automatically assigned the "omitempty" option, as TOML
explicitly does not handle null values (saying instead the label should be
dropped).

Tree structural types and corresponding marshal types:

  *Tree                            (*)struct, (*)map[string]interface{}
  []*Tree                          (*)[](*)struct, (*)[](*)map[string]interface{}
  []interface{} (as interface{})   (*)[]primitive, (*)[]([]interface{})
  interface{}                      (*)primitive

Tree primitive types and corresponding marshal types:

  uint64     uint, uint8-uint64, pointers to same
  int64      int, int8-uint64, pointers to same
  float64    float32, float64, pointers to same
  string     string, pointers to same
  bool       bool, pointers to same
  time.LocalTime  time.LocalTime{}, pointers to same

For additional flexibility, use the Encoder API.
*/
func Marshal(v interface{}) ([]byte, error) {
	return NewEncoder(nil).marshal(v)
}

// Encoder writes TOML values to an output stream.
type Encoder struct {
	w io.Writer
	encOpts
	annotation
	line  int
	col   int
	order marshalOrder
}

// NewEncoder returns a new encoder that writes to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{
		w:          w,
		encOpts:    encOptsDefaults,
		annotation: annotationDefault,
		line:       0,
		col:        1,
		order:      OrderAlphabetical,
	}
}

// Encode writes the TOML encoding of v to the stream.
//
// See the documentation for Marshal for details.
func (e *Encoder) Encode(v interface{}) error {
	b, err := e.marshal(v)
	if err != nil {
		return err
	}
	if _, err := e.w.Write(b); err != nil {
		return err
	}
	return nil
}

// QuoteMapKeys sets up the encoder to encode
// maps with string type keys with quoted TOML keys.
//
// This relieves the character limitations on map keys.
func (e *Encoder) QuoteMapKeys(v bool) *Encoder {
	e.quoteMapKeys = v
	return e
}

// ArraysWithOneElementPerLine sets up the encoder to encode arrays
// with more than one element on multiple lines instead of one.
//
// For example:
//
//   A = [1,2,3]
//
// Becomes
//
//   A = [
//     1,
//     2,
//     3,
//   ]
func (e *Encoder) ArraysWithOneElementPerLine(v bool) *Encoder {
	e.arraysOneElementPerLine = v
	return e
}

// Order allows to change in which order fields will be written to the output stream.
func (e *Encoder) Order(ord marshalOrder) *Encoder {
	e.order = ord
	return e
}

// SetTagName allows changing default tag "toml"
func (e *Encoder) SetTagName(v string) *Encoder {
	e.tag = v
	return e
}

// SetTagComment allows changing default tag "comment"
func (e *Encoder) SetTagComment(v string) *Encoder {
	e.comment = v
	return e
}

// SetTagCommented allows changing default tag "commented"
func (e *Encoder) SetTagCommented(v string) *Encoder {
	e.commented = v
	return e
}

// SetTagMultiline allows changing default tag "multiline"
func (e *Encoder) SetTagMultiline(v string) *Encoder {
	e.multiline = v
	return e
}

func (e *Encoder) marshal(v interface{}) ([]byte, error) {
	mtype := reflect.TypeOf(v)

	switch mtype.Kind() {
	case reflect.Struct, reflect.Map:
	case reflect.Ptr:
		if mtype.Elem().Kind() != reflect.Struct {
			return []byte{}, errors.New("Only pointer to struct can be marshaled to TOML")
		}
	default:
		return []byte{}, errors.New("Only a struct or map can be marshaled to TOML")
	}

	sval := reflect.ValueOf(v)
	if isCustomMarshaler(mtype) {
		return callCustomMarshaler(sval)
	}
	t, err := e.valueToTree(mtype, sval)
	if err != nil {
		return []byte{}, err
	}

	var buf bytes.Buffer
	_, err = t.writeToOrdered(&buf, "", "", 0, e.arraysOneElementPerLine, e.order, false)

	return buf.Bytes(), err
}

// Create next tree with a position based on Encoder.line
func (e *Encoder) nextTree() *Tree {
	return newTreeWithPosition(Position{Line: e.line, Col: 1})
}

// Convert given marshal struct or map value to toml tree
func (e *Encoder) valueToTree(mtype reflect.Type, mval reflect.Value) (*Tree, error) {
	if mtype.Kind() == reflect.Ptr {
		return e.valueToTree(mtype.Elem(), mval.Elem())
	}
	tval := e.nextTree()
	switch mtype.Kind() {
	case reflect.Struct:
		switch mval.Interface().(type) {
		case Tree:
			reflect.ValueOf(tval).Elem().Set(mval)
		default:
			for i := 0; i < mtype.NumField(); i++ {
				mtypef, mvalf := mtype.Field(i), mval.Field(i)
				opts := tomlOptions(mtypef, e.annotation)
				if opts.include && ((mtypef.Type.Kind() != reflect.Interface && !opts.omitempty) || !isZero(mvalf)) {
					val, err := e.valueToToml(mtypef.Type, mvalf)
					if err != nil {
						return nil, err
					}

					tval.SetWithOptions(opts.name, SetOptions{
						Comment:   opts.comment,
						Commented: opts.commented,
						Multiline: opts.multiline,
					}, val)
				}
			}
		}
	case reflect.Map:
		keys := mval.MapKeys()
		if e.order == OrderPreserve && len(keys) > 0 {
			// Sorting []reflect.Value is not straight forward.
			//
			// OrderPreserve will support deterministic results when string is used
			// as the key to maps.
			typ := keys[0].Type()
			kind := keys[0].Kind()
			if kind == reflect.String {
				ikeys := make([]string, len(keys))
				for i := range keys {
					ikeys[i] = keys[i].Interface().(string)
				}
				sort.Strings(ikeys)
				for i := range ikeys {
					keys[i] = reflect.ValueOf(ikeys[i]).Convert(typ)
				}
			}
		}
		for _, key := range keys {
			mvalf := mval.MapIndex(key)
			if (mtype.Elem().Kind() == reflect.Ptr || mtype.Elem().Kind() == reflect.Interface) && mvalf.IsNil() {
				continue
			}
			val, err := e.valueToToml(mtype.Elem(), mvalf)
			if err != nil {
				return nil, err
			}
			if e.quoteMapKeys {
				keyStr, err := tomlValueStringRepresentation(key.String(), "", "", e.arraysOneElementPerLine)
				if err != nil {
					return nil, err
				}
				tval.SetPath([]string{keyStr}, val)
			} else {
				tval.Set(key.String(), val)
			}
		}
	}
	return tval, nil
}

// Convert given marshal slice to slice of Toml trees
func (e *Encoder) valueToTreeSlice(mtype reflect.Type, mval reflect.Value) ([]*Tree, error) {
	tval := make([]*Tree, mval.Len(), mval.Len())
	for i := 0; i < mval.Len(); i++ {
		val, err := e.valueToTree(mtype.Elem(), mval.Index(i))
		if err != nil {
			return nil, err
		}
		tval[i] = val
	}
	return tval, nil
}

// Convert given marshal slice to slice of toml values
func (e *Encoder) valueToOtherSlice(mtype reflect.Type, mval reflect.Value) (interface{}, error) {
	if mtype.Elem().Kind() == reflect.Interface {
		return nil, fmt.Errorf("marshal can't handle []interface{}")
	}
	tval := make([]interface{}, mval.Len(), mval.Len())
	for i := 0; i < mval.Len(); i++ {
		val, err := e.valueToToml(mtype.Elem(), mval.Index(i))
		if err != nil {
			return nil, err
		}
		tval[i] = val
	}
	return tval, nil
}

// Convert given marshal value to toml value
func (e *Encoder) valueToToml(mtype reflect.Type, mval reflect.Value) (interface{}, error) {
	e.line++
	if mtype.Kind() == reflect.Ptr {
		return e.valueToToml(mtype.Elem(), mval.Elem())
	}
	if mtype.Kind() == reflect.Interface {
		return e.valueToToml(mval.Elem().Type(), mval.Elem())
	}
	switch {
	case isCustomMarshaler(mtype):
		return callCustomMarshaler(mval)
	case isTree(mtype):
		return e.valueToTree(mtype, mval)
	case isTreeSequence(mtype):
		return e.valueToTreeSlice(mtype, mval)
	case isOtherSequence(mtype):
		return e.valueToOtherSlice(mtype, mval)
	default:
		switch mtype.Kind() {
		case reflect.Bool:
			return mval.Bool(), nil
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if mtype.Kind() == reflect.Int64 && mtype == reflect.TypeOf(time.Duration(1)) {
				return fmt.Sprint(mval), nil
			}
			return mval.Int(), nil
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return mval.Uint(), nil
		case reflect.Float32, reflect.Float64:
			return mval.Float(), nil
		case reflect.String:
			return mval.String(), nil
		case reflect.Struct:
			return mval.Interface(), nil
		default:
			return nil, fmt.Errorf("Marshal can't handle %v(%v)", mtype, mtype.Kind())
		}
	}
}

// Unmarshal attempts to unmarshal the Tree into a Go struct pointed by v.
// Neither Unmarshaler interfaces nor UnmarshalTOML functions are supported for
// sub-structs, and only definite types can be unmarshaled.
func (t *Tree) Unmarshal(v interface{}) error {
	d := Decoder{tval: t, tagName: tagFieldName}
	return d.unmarshal(v)
}

// Marshal returns the TOML encoding of Tree.
// See Marshal() documentation for types mapping table.
func (t *Tree) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	_, err := t.WriteTo(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Unmarshal parses the TOML-encoded data and stores the result in the value
// pointed to by v. Behavior is similar to the Go json encoder, except that there
// is no concept of an Unmarshaler interface or UnmarshalTOML function for
// sub-structs, and currently only definite types can be unmarshaled to (i.e. no
// `interface{}`).
//
// The following struct annotations are supported:
//
//   toml:"Field" Overrides the field's name to map to.
//   default:"foo" Provides a default value.
//
// For default values, only fields of the following types are supported:
//   * string
//   * bool
//   * int
//   * int64
//   * float64
//
// See Marshal() documentation for types mapping table.
func Unmarshal(data []byte, v interface{}) error {
	t, err := LoadReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	return t.Unmarshal(v)
}

// Decoder reads and decodes TOML values from an input stream.
type Decoder struct {
	r    io.Reader
	tval *Tree
	encOpts
	tagName string
}

// NewDecoder returns a new decoder that reads from r.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		r:       r,
		encOpts: encOptsDefaults,
		tagName: tagFieldName,
	}
}

// Decode reads a TOML-encoded value from it's input
// and unmarshals it in the value pointed at by v.
//
// See the documentation for Marshal for details.
func (d *Decoder) Decode(v interface{}) error {
	var err error
	d.tval, err = LoadReader(d.r)
	if err != nil {
		return err
	}
	return d.unmarshal(v)
}

// SetTagName allows changing default tag "toml"
func (d *Decoder) SetTagName(v string) *Decoder {
	d.tagName = v
	return d
}

func (d *Decoder) unmarshal(v interface{}) error {
	mtype := reflect.TypeOf(v)
	if mtype.Kind() != reflect.Ptr {
		return errors.New("only a pointer to struct or map can be unmarshaled from TOML")
	}

	elem := mtype.Elem()

	switch elem.Kind() {
	case reflect.Struct, reflect.Map:
	default:
		return errors.New("only a pointer to struct or map can be unmarshaled from TOML")
	}

	vv := reflect.ValueOf(v).Elem()

	sval, err := d.valueFromTree(elem, d.tval, &vv)
	if err != nil {
		return err
	}
	reflect.ValueOf(v).Elem().Set(sval)
	return nil
}

// Convert toml tree to marshal struct or map, using marshal type. When mval1
// is non-nil, merge fields into the given value instead of allocating a new one.
func (d *Decoder) valueFromTree(mtype reflect.Type, tval *Tree, mval1 *reflect.Value) (reflect.Value, error) {
	if mtype.Kind() == reflect.Ptr {
		return d.unwrapPointer(mtype, tval, mval1)
	}
	var mval reflect.Value
	switch mtype.Kind() {
	case reflect.Struct:
		if mval1 != nil {
			mval = *mval1
		} else {
			mval = reflect.New(mtype).Elem()
		}

		switch mval.Interface().(type) {
		case Tree:
			mval.Set(reflect.ValueOf(tval).Elem())
		default:
			for i := 0; i < mtype.NumField(); i++ {
				mtypef := mtype.Field(i)
				an := annotation{tag: d.tagName}
				opts := tomlOptions(mtypef, an)
				if !opts.include {
					continue
				}
				baseKey := opts.name
				keysToTry := []string{
					baseKey,
					strings.ToLower(baseKey),
					strings.ToTitle(baseKey),
					strings.ToLower(string(baseKey[0])) + baseKey[1:],
				}

				found := false
				if tval != nil {
					for _, key := range keysToTry {
						exists := tval.Has(key)
						if !exists {
							continue
						}
						val := tval.Get(key)
						fval := mval.Field(i)
						mvalf, err := d.valueFromToml(mtypef.Type, val, &fval)
						if err != nil {
							return mval, formatError(err, tval.GetPosition(key))
						}
						mval.Field(i).Set(mvalf)
						found = true
						break
					}
				}

				if !found && opts.defaultValue != "" {
					mvalf := mval.Field(i)
					var val interface{}
					var err error
					switch mvalf.Kind() {
					case reflect.Bool:
						val, err = strconv.ParseBool(opts.defaultValue)
						if err != nil {
							return mval.Field(i), err
						}
					case reflect.Int:
						val, err = strconv.Atoi(opts.defaultValue)
						if err != nil {
							return mval.Field(i), err
						}
					case reflect.String:
						val = opts.defaultValue
					case reflect.Int64:
						val, err = strconv.ParseInt(opts.defaultValue, 10, 64)
						if err != nil {
							return mval.Field(i), err
						}
					case reflect.Float64:
						val, err = strconv.ParseFloat(opts.defaultValue, 64)
						if err != nil {
							return mval.Field(i), err
						}
					default:
						return mval.Field(i), fmt.Errorf("unsuported field type for default option")
					}
					mval.Field(i).Set(reflect.ValueOf(val))
				}

				// save the old behavior above and try to check structs
				if !found && opts.defaultValue == "" && mtypef.Type.Kind() == reflect.Struct {
					tmpTval := tval
					if !mtypef.Anonymous {
						tmpTval = nil
					}
					v, err := d.valueFromTree(mtypef.Type, tmpTval, nil)
					if err != nil {
						return v, err
					}
					mval.Field(i).Set(v)
				}
			}
		}
	case reflect.Map:
		mval = reflect.MakeMap(mtype)
		for _, key := range tval.Keys() {
			// TODO: path splits key
			val := tval.GetPath([]string{key})
			mvalf, err := d.valueFromToml(mtype.Elem(), val, nil)
			if err != nil {
				return mval, formatError(err, tval.GetPosition(key))
			}
			mval.SetMapIndex(reflect.ValueOf(key).Convert(mtype.Key()), mvalf)
		}
	}
	return mval, nil
}

// Convert toml value to marshal struct/map slice, using marshal type
func (d *Decoder) valueFromTreeSlice(mtype reflect.Type, tval []*Tree) (reflect.Value, error) {
	mval := reflect.MakeSlice(mtype, len(tval), len(tval))
	for i := 0; i < len(tval); i++ {
		val, err := d.valueFromTree(mtype.Elem(), tval[i], nil)
		if err != nil {
			return mval, err
		}
		mval.Index(i).Set(val)
	}
	return mval, nil
}

// Convert toml value to marshal primitive slice, using marshal type
func (d *Decoder) valueFromOtherSlice(mtype reflect.Type, tval []interface{}) (reflect.Value, error) {
	mval := reflect.MakeSlice(mtype, len(tval), len(tval))
	for i := 0; i < len(tval); i++ {
		val, err := d.valueFromToml(mtype.Elem(), tval[i], nil)
		if err != nil {
			return mval, err
		}
		mval.Index(i).Set(val)
	}
	return mval, nil
}

// Convert toml value to marshal value, using marshal type. When mval1 is non-nil
// and the given type is a struct value, merge fields into it.
func (d *Decoder) valueFromToml(mtype reflect.Type, tval interface{}, mval1 *reflect.Value) (reflect.Value, error) {
	if mtype.Kind() == reflect.Ptr {
		return d.unwrapPointer(mtype, tval, mval1)
	}

	switch t := tval.(type) {
	case *Tree:
		var mval11 *reflect.Value
		if mtype.Kind() == reflect.Struct {
			mval11 = mval1
		}

		if isTree(mtype) {
			return d.valueFromTree(mtype, t, mval11)
		}

		if mtype.Kind() == reflect.Interface {
			if mval1 == nil || mval1.IsNil() {
				return d.valueFromTree(reflect.TypeOf(map[string]interface{}{}), t, nil)
			} else {
				return d.valueFromToml(mval1.Elem().Type(), t, nil)
			}
		}

		return reflect.ValueOf(nil), fmt.Errorf("Can't convert %v(%T) to a tree", tval, tval)
	case []*Tree:
		if isTreeSequence(mtype) {
			return d.valueFromTreeSlice(mtype, t)
		}
		if mtype.Kind() == reflect.Interface {
			if mval1 == nil || mval1.IsNil() {
				return d.valueFromTreeSlice(reflect.TypeOf([]map[string]interface{}{}), t)
			} else {
				ival := mval1.Elem()
				return d.valueFromToml(mval1.Elem().Type(), t, &ival)
			}
		}
		return reflect.ValueOf(nil), fmt.Errorf("Can't convert %v(%T) to trees", tval, tval)
	case []interface{}:
		if isOtherSequence(mtype) {
			return d.valueFromOtherSlice(mtype, t)
		}
		if mtype.Kind() == reflect.Interface {
			if mval1 == nil || mval1.IsNil() {
				return d.valueFromOtherSlice(reflect.TypeOf([]interface{}{}), t)
			} else {
				ival := mval1.Elem()
				return d.valueFromToml(mval1.Elem().Type(), t, &ival)
			}
		}
		return reflect.ValueOf(nil), fmt.Errorf("Can't convert %v(%T) to a slice", tval, tval)
	default:
		switch mtype.Kind() {
		case reflect.Bool, reflect.Struct:
			val := reflect.ValueOf(tval)

			switch val.Type() {
			case localDateType:
				localDate := val.Interface().(LocalDate)
				switch mtype {
				case timeType:
					return reflect.ValueOf(time.Date(localDate.Year, localDate.Month, localDate.Day, 0, 0, 0, 0, time.Local)), nil
				}
			case localDateTimeType:
				localDateTime := val.Interface().(LocalDateTime)
				switch mtype {
				case timeType:
					return reflect.ValueOf(time.Date(
						localDateTime.Date.Year,
						localDateTime.Date.Month,
						localDateTime.Date.Day,
						localDateTime.Time.Hour,
						localDateTime.Time.Minute,
						localDateTime.Time.Second,
						localDateTime.Time.Nanosecond,
						time.Local)), nil
				}
			}

			// if this passes for when mtype is reflect.Struct, tval is a time.LocalTime
			if !val.Type().ConvertibleTo(mtype) {
				return reflect.ValueOf(nil), fmt.Errorf("Can't convert %v(%T) to %v", tval, tval, mtype.String())
			}

			return val.Convert(mtype), nil
		case reflect.String:
			val := reflect.ValueOf(tval)
			// stupidly, int64 is convertible to string. So special case this.
			if !val.Type().ConvertibleTo(mtype) || val.Kind() == reflect.Int64 {
				return reflect.ValueOf(nil), fmt.Errorf("Can't convert %v(%T) to %v", tval, tval, mtype.String())
			}

			return val.Convert(mtype), nil
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			val := reflect.ValueOf(tval)
			if mtype.Kind() == reflect.Int64 && mtype == reflect.TypeOf(time.Duration(1)) && val.Kind() == reflect.String {
				d, err := time.ParseDuration(val.String())
				if err != nil {
					return reflect.ValueOf(nil), fmt.Errorf("Can't convert %v(%T) to %v. %s", tval, tval, mtype.String(), err)
				}
				return reflect.ValueOf(d), nil
			}
			if !val.Type().ConvertibleTo(mtype) {
				return reflect.ValueOf(nil), fmt.Errorf("Can't convert %v(%T) to %v", tval, tval, mtype.String())
			}
			if reflect.Indirect(reflect.New(mtype)).OverflowInt(val.Convert(mtype).Int()) {
				return reflect.ValueOf(nil), fmt.Errorf("%v(%T) would overflow %v", tval, tval, mtype.String())
			}

			return val.Convert(mtype), nil
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			val := reflect.ValueOf(tval)
			if !val.Type().ConvertibleTo(mtype) {
				return reflect.ValueOf(nil), fmt.Errorf("Can't convert %v(%T) to %v", tval, tval, mtype.String())
			}

			if val.Convert(reflect.TypeOf(int(1))).Int() < 0 {
				return reflect.ValueOf(nil), fmt.Errorf("%v(%T) is negative so does not fit in %v", tval, tval, mtype.String())
			}
			if reflect.Indirect(reflect.New(mtype)).OverflowUint(uint64(val.Convert(mtype).Uint())) {
				return reflect.ValueOf(nil), fmt.Errorf("%v(%T) would overflow %v", tval, tval, mtype.String())
			}

			return val.Convert(mtype), nil
		case reflect.Float32, reflect.Float64:
			val := reflect.ValueOf(tval)
			if !val.Type().ConvertibleTo(mtype) {
				return reflect.ValueOf(nil), fmt.Errorf("Can't convert %v(%T) to %v", tval, tval, mtype.String())
			}
			if reflect.Indirect(reflect.New(mtype)).OverflowFloat(val.Convert(mtype).Float()) {
				return reflect.ValueOf(nil), fmt.Errorf("%v(%T) would overflow %v", tval, tval, mtype.String())
			}

			return val.Convert(mtype), nil
		case reflect.Interface:
			if mval1 == nil || mval1.IsNil() {
				return reflect.ValueOf(tval), nil
			} else {
				ival := mval1.Elem()
				return d.valueFromToml(mval1.Elem().Type(), t, &ival)
			}
		default:
			return reflect.ValueOf(nil), fmt.Errorf("Can't convert %v(%T) to %v(%v)", tval, tval, mtype, mtype.Kind())
		}
	}
}

func (d *Decoder) unwrapPointer(mtype reflect.Type, tval interface{}, mval1 *reflect.Value) (reflect.Value, error) {
	var melem *reflect.Value

	if mval1 != nil && !mval1.IsNil() && (mtype.Elem().Kind() == reflect.Struct || mtype.Elem().Kind() == reflect.Interface) {
		elem := mval1.Elem()
		melem = &elem
	}

	val, err := d.valueFromToml(mtype.Elem(), tval, melem)
	if err != nil {
		return reflect.ValueOf(nil), err
	}
	mval := reflect.New(mtype.Elem())
	mval.Elem().Set(val)
	return mval, nil
}

func tomlOptions(vf reflect.StructField, an annotation) tomlOpts {
	tag := vf.Tag.Get(an.tag)
	parse := strings.Split(tag, ",")
	var comment string
	if c := vf.Tag.Get(an.comment); c != "" {
		comment = c
	}
	commented, _ := strconv.ParseBool(vf.Tag.Get(an.commented))
	multiline, _ := strconv.ParseBool(vf.Tag.Get(an.multiline))
	defaultValue := vf.Tag.Get(tagDefault)
	result := tomlOpts{
		name:         vf.Name,
		comment:      comment,
		commented:    commented,
		multiline:    multiline,
		include:      true,
		omitempty:    false,
		defaultValue: defaultValue,
	}
	if parse[0] != "" {
		if parse[0] == "-" && len(parse) == 1 {
			result.include = false
		} else {
			result.name = strings.Trim(parse[0], " ")
		}
	}
	if vf.PkgPath != "" {
		result.include = false
	}
	if len(parse) > 1 && strings.Trim(parse[1], " ") == "omitempty" {
		result.omitempty = true
	}
	if vf.Type.Kind() == reflect.Ptr {
		result.omitempty = true
	}
	return result
}

func isZero(val reflect.Value) bool {
	switch val.Type().Kind() {
	case reflect.Map:
		fallthrough
	case reflect.Array:
		fallthrough
	case reflect.Slice:
		return val.Len() == 0
	default:
		return reflect.DeepEqual(val.Interface(), reflect.Zero(val.Type()).Interface())
	}
}

func formatError(err error, pos Position) error {
	if err.Error()[0] == '(' { // Error already contains position information
		return err
	}
	return fmt.Errorf("%s: %s", pos, err)
}
