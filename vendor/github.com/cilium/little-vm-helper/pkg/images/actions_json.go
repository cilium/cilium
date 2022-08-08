package images

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// some code so that we can marshall/unmarshal all instances of ActionOp.
// the only thing new types need to do is to add themselves to actionOpInstances.

var actionOpMap map[string]ActionOp = createActionOpMap()

func createActionOpMap() map[string]ActionOp {
	ret := make(map[string]ActionOp, len(actionOpInstances))
	for _, op := range actionOpInstances {
		ret[op.ActionOpName()] = op
	}
	return ret
}

// CopyFile copies a file from the host inside an image
type CopyFile struct {
	HostPath  string
	ImagePath string
}

type actionWrapper struct {
	Comment string
	Type    string `json:"type"` // NB: has to match the dict below
	Op      json.RawMessage
}

func (a *Action) MarshalJSON() (b []byte, e error) {

	val := map[string]interface{}{
		"comment": a.Comment,
		"op":      a.Op,
		"type":    a.Op.ActionOpName(),
	}

	return json.Marshal(val)
}

func (a *Action) UnmarshalJSON(b []byte) error {
	var w actionWrapper
	err := json.Unmarshal(b, &w)
	if err != nil {
		return err
	}

	a.Comment = w.Comment
	opInstance, ok := actionOpMap[w.Type]
	if !ok {
		return fmt.Errorf("unknown op type '%s'", w.Type)
	}

	// opInstance is *T so we need .Elem() to get T
	opTy := reflect.TypeOf(opInstance).Elem()
	op := reflect.New(opTy).Interface().(ActionOp)
	err = json.Unmarshal(w.Op, op)
	if err != nil {
		return err
	}
	a.Op = op

	return nil
}
