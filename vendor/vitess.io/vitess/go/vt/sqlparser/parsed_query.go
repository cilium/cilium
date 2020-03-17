// Copyright 2012, Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlparser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/youtube/vitess/go/sqltypes"
	"github.com/youtube/vitess/go/vt/utils"

	querypb "github.com/youtube/vitess/go/vt/proto/query"
)

type bindLocation struct {
	offset, length int
}

// ParsedQuery represents a parsed query where
// bind locations are precompued for fast substitutions.
type ParsedQuery struct {
	Query         string
	bindLocations []bindLocation
}

// GenerateQuery generates a query by substituting the specified
// bindVariables.
func (pq *ParsedQuery) GenerateQuery(bindVariables map[string]interface{}) ([]byte, error) {
	if len(pq.bindLocations) == 0 {
		return []byte(pq.Query), nil
	}
	buf := bytes.NewBuffer(make([]byte, 0, len(pq.Query)))
	current := 0
	for _, loc := range pq.bindLocations {
		buf.WriteString(pq.Query[current:loc.offset])
		name := pq.Query[loc.offset : loc.offset+loc.length]
		supplied, _, err := FetchBindVar(name, bindVariables)
		if err != nil {
			return nil, err
		}
		if err := EncodeValue(buf, supplied); err != nil {
			return nil, err
		}
		current = loc.offset + loc.length
	}
	buf.WriteString(pq.Query[current:])
	return buf.Bytes(), nil
}

// MarshalJSON is a custom JSON marshaler for ParsedQuery.
// Note that any queries longer that 512 bytes will be truncated.
func (pq *ParsedQuery) MarshalJSON() ([]byte, error) {
	return json.Marshal(utils.TruncateQuery(pq.Query))
}

// EncodeValue encodes one bind variable value into the query.
func EncodeValue(buf *bytes.Buffer, value interface{}) error {
	switch bindVal := value.(type) {
	case nil:
		buf.WriteString("null")
	case sqltypes.Value:
		bindVal.EncodeSQL(buf)
	case []sqltypes.Value:
		for i, bv := range bindVal {
			if i != 0 {
				buf.WriteString(", ")
			}
			bv.EncodeSQL(buf)
		}
	case [][]sqltypes.Value:
		for i, bvs := range bindVal {
			if i != 0 {
				buf.WriteString(", ")
			}
			buf.WriteByte('(')
			for j, bv := range bvs {
				if j != 0 {
					buf.WriteString(", ")
				}
				bv.EncodeSQL(buf)
			}
			buf.WriteByte(')')
		}
	case []interface{}:
		buf.WriteByte('(')
		for i, v := range bindVal {
			if i != 0 {
				buf.WriteString(", ")
			}
			if err := EncodeValue(buf, v); err != nil {
				return err
			}
		}
		buf.WriteByte(')')
	case TupleEqualityList:
		if err := bindVal.Encode(buf); err != nil {
			return err
		}
	case *querypb.BindVariable:
		if bindVal.Type == querypb.Type_TUPLE {
			buf.WriteByte('(')
			for i, bv := range bindVal.Values {
				if i != 0 {
					buf.WriteString(", ")
				}
				v, err := sqltypes.ValueFromBytes(bv.Type, bv.Value)
				if err != nil {
					return err
				}
				v.EncodeSQL(buf)
			}
			buf.WriteByte(')')
		} else {
			v, err := sqltypes.ValueFromBytes(bindVal.Type, bindVal.Value)
			if err != nil {
				return err
			}
			v.EncodeSQL(buf)
		}
	default:
		v, err := sqltypes.BuildValue(bindVal)
		if err != nil {
			return err
		}
		v.EncodeSQL(buf)
	}
	return nil
}

// TupleEqualityList is for generating equality constraints
// for tables that have composite primary keys.
type TupleEqualityList struct {
	Columns []ColIdent
	Rows    [][]sqltypes.Value
}

// Encode generates the where clause constraints for the tuple
// equality.
func (tpl *TupleEqualityList) Encode(buf *bytes.Buffer) error {
	if len(tpl.Rows) == 0 {
		return errors.New("cannot encode with 0 rows")
	}
	if len(tpl.Columns) == 1 {
		return tpl.encodeAsIN(buf)
	}
	return tpl.encodeAsEquality(buf)
}

func (tpl *TupleEqualityList) encodeAsIN(buf *bytes.Buffer) error {
	Append(buf, tpl.Columns[0])
	buf.WriteString(" in (")
	for i, r := range tpl.Rows {
		if len(r) != 1 {
			return errors.New("values don't match column count")
		}
		if i != 0 {
			buf.WriteString(", ")
		}
		r[0].EncodeSQL(buf)
	}
	buf.WriteByte(')')
	return nil
}

func (tpl *TupleEqualityList) encodeAsEquality(buf *bytes.Buffer) error {
	for i, r := range tpl.Rows {
		if i != 0 {
			buf.WriteString(" or ")
		}
		buf.WriteString("(")
		for j, c := range tpl.Columns {
			if j != 0 {
				buf.WriteString(" and ")
			}
			Append(buf, c)
			buf.WriteString(" = ")
			r[j].EncodeSQL(buf)
		}
		buf.WriteByte(')')
	}
	return nil
}

// FetchBindVar resolves the bind variable by fetching it from bindVariables.
func FetchBindVar(name string, bindVariables map[string]interface{}) (val interface{}, isList bool, err error) {
	name = name[1:]
	if name[0] == ':' {
		name = name[1:]
		isList = true
	}
	supplied, ok := bindVariables[name]
	if !ok {
		return nil, false, fmt.Errorf("missing bind var %s", name)
	}

	if isList {
		// two ways to have a list:
		// - []interface{}
		// - *querypb.BindVariable with Type == querypb.Type_TUPLE

		if list, gotList := supplied.([]interface{}); gotList {
			if len(list) == 0 {
				return nil, false, fmt.Errorf("empty list supplied for %s", name)
			}
			return list, true, nil
		}

		if bv, gotBindVariable := supplied.(*querypb.BindVariable); gotBindVariable {
			if bv.Type == querypb.Type_TUPLE {
				if len(bv.Values) == 0 {
					return nil, false, fmt.Errorf("empty list supplied for %s", name)
				}
				return bv, true, nil
			}

			return nil, false, fmt.Errorf("unexpected list arg type *querypb.BindVariable(%v) for key %s", bv.Type, name)
		}

		return nil, false, fmt.Errorf("unexpected list arg type %T for key %s", supplied, name)
	}

	// check we didn't get a list.
	if _, gotList := supplied.([]interface{}); gotList {
		return nil, false, fmt.Errorf("unexpected arg type %T for key %s", supplied, name)
	}
	if bv, gotBindVariable := supplied.(*querypb.BindVariable); gotBindVariable && bv.Type == querypb.Type_TUPLE {
		return nil, false, fmt.Errorf("unexpected arg type *querypb.BindVariable(TUPLE) for key %s", name)
	}

	return supplied, false, nil
}
