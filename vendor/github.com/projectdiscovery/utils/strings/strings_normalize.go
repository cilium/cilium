package stringsutil

import (
	"strings"

	"github.com/microcosm-cc/bluemonday"
)

type NormalizeOptions struct {
	TrimSpaces bool
	StripHTML  bool
	Lowercase  bool
	Uppercase  bool
}

var DefaultNormalizeOptions NormalizeOptions = NormalizeOptions{
	TrimSpaces: true,
	StripHTML:  true,
}

var HTMLPolicy *bluemonday.Policy = bluemonday.StrictPolicy()

func NormalizeWithOptions(data string, options NormalizeOptions) string {
	if options.TrimSpaces {
		data = strings.TrimSpace(data)
	}

	if options.Lowercase {
		data = strings.ToLower(data)
	}

	if options.Uppercase {
		data = strings.ToUpper(data)
	}

	if options.StripHTML {
		data = HTMLPolicy.Sanitize(data)
	}

	return data
}

func Normalize(data string) string {
	return NormalizeWithOptions(data, DefaultNormalizeOptions)
}
