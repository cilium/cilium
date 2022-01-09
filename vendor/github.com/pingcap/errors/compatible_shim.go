// Copyright 2020 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// See the License for the specific language governing permissions and
// limitations under the License.

package errors

import (
	"encoding/json"
	"strconv"
	"strings"
)

// class2RFCCode is used for compatible with old version of TiDB. When
// marshal Error to json, old version of TiDB contain a 'class' field
// which is represented for error class. In order to parse and convert
// json to errors.Error, using this map to convert error class to RFC
// error code text. here is reference:
// https://github.com/pingcap/parser/blob/release-3.0/terror/terror.go#L58
var class2RFCCode = map[int]string{
	1:  "autoid",
	2:  "ddl",
	3:  "domain",
	4:  "evaluator",
	5:  "executor",
	6:  "expression",
	7:  "admin",
	8:  "kv",
	9:  "meta",
	10: "planner",
	11: "parser",
	12: "perfschema",
	13: "privilege",
	14: "schema",
	15: "server",
	16: "struct",
	17: "variable",
	18: "xeval",
	19: "table",
	20: "types",
	21: "global",
	22: "mocktikv",
	23: "json",
	24: "tikv",
	25: "session",
	26: "plugin",
	27: "util",
}
var rfcCode2class map[string]int

func init() {
	rfcCode2class = make(map[string]int)
	for k, v := range class2RFCCode {
		rfcCode2class[v] = k
	}
}

// MarshalJSON implements json.Marshaler interface.
// aware that this function cannot save a 'registered' status,
// since we cannot access the registry when unmarshaling,
// and the original global registry would be removed here.
// This function is reserved for compatibility.
func (e *Error) MarshalJSON() ([]byte, error) {
	ec := strings.Split(string(e.codeText), ":")[0]
	return json.Marshal(&jsonError{
		Class:   rfcCode2class[ec],
		Code:    int(e.code),
		Msg:     e.GetMsg(),
		RFCCode: string(e.codeText),
	})
}

// UnmarshalJSON implements json.Unmarshaler interface.
// aware that this function cannot create a 'registered' error,
// since we cannot access the registry in this context,
// and the original global registry is removed.
// This function is reserved for compatibility.
func (e *Error) UnmarshalJSON(data []byte) error {
	tErr := &jsonError{}
	if err := json.Unmarshal(data, &tErr); err != nil {
		return Trace(err)
	}
	e.codeText = ErrCodeText(tErr.RFCCode)
	if tErr.RFCCode == "" && tErr.Class > 0 {
		e.codeText = ErrCodeText(class2RFCCode[tErr.Class] + ":" + strconv.Itoa(tErr.Code))
	}
	e.code = ErrCode(tErr.Code)
	e.message = tErr.Msg
	return nil
}
