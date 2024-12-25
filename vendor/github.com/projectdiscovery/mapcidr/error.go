package mapcidr

import "github.com/pkg/errors"

var (
	ParseIPError error = errors.New("Couldn't parse IP")
)
