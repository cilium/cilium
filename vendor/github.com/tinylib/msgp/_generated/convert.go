package _generated

import "errors"

//go:generate msgp

//msgp:shim ConvertStringVal as:string using:fromConvertStringVal/toConvertStringVal mode:convert
//msgp:ignore ConvertStringVal

func fromConvertStringVal(v ConvertStringVal) (string, error) {
	return string(v), nil
}

func toConvertStringVal(s string) (ConvertStringVal, error) {
	return ConvertStringVal(s), nil
}

type ConvertStringVal string

type ConvertString struct {
	String ConvertStringVal
}

type ConvertStringSlice struct {
	Strings []ConvertStringVal
}

type ConvertStringMapValue struct {
	Strings map[string]ConvertStringVal
}

//msgp:shim ConvertIntfVal as:interface{} using:fromConvertIntfVal/toConvertIntfVal mode:convert
//msgp:ignore ConvertIntfVal

func fromConvertIntfVal(v ConvertIntfVal) (interface{}, error) {
	return v.Test, nil
}

func toConvertIntfVal(s interface{}) (ConvertIntfVal, error) {
	return ConvertIntfVal{Test: s.(string)}, nil
}

type ConvertIntfVal struct {
	Test string
}

type ConvertIntf struct {
	Intf ConvertIntfVal
}

//msgp:shim ConvertErrVal as:string using:fromConvertErrVal/toConvertErrVal mode:convert
//msgp:ignore ConvertErrVal

var (
	errConvertFrom = errors.New("error: convert from")
	errConvertTo   = errors.New("error: convert to")
)

const (
	fromFailStr = "fromfail"
	toFailStr   = "tofail"
)

func fromConvertErrVal(v ConvertErrVal) (string, error) {
	s := string(v)
	if s == fromFailStr {
		return "", errConvertFrom
	}
	return s, nil
}

func toConvertErrVal(s string) (ConvertErrVal, error) {
	if s == toFailStr {
		return ConvertErrVal(""), errConvertTo
	}
	return ConvertErrVal(s), nil
}

type ConvertErrVal string

type ConvertErr struct {
	Err ConvertErrVal
}
