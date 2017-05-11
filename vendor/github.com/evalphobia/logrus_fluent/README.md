[![Build Status](https://travis-ci.org/evalphobia/logrus_fluent.svg?branch=master)](https://travis-ci.org/evalphobia/logrus_fluent)  [![Coverage Status](https://coveralls.io/repos/evalphobia/logrus_fluent/badge.svg?branch=master&service=github)](https://coveralls.io/github/evalphobia/logrus_fluent?branch=master) [![GoDoc](https://godoc.org/github.com/evalphobia/logrus_fluent?status.svg)](https://godoc.org/github.com/evalphobia/logrus_fluent)


# Fluentd Hook for Logrus <img src="http://i.imgur.com/hTeVwmJ.png" width="40" height="40" alt=":walrus:" class="emoji" title=":walrus:"/>

## Usage

```go
import (
	"github.com/Sirupsen/logrus"
	"github.com/evalphobia/logrus_fluent"
)

func main() {
	hook, err := logrus_fluent.New("localhost", 24224)
	if err != nil {
		panic(err)
	}

	// set custom fire level
	hook.SetLevels([]logrus.Level{
		logrus.PanicLevel,
		logrus.ErrorLevel,
	})

	// set static tag
	hook.SetTag("original.tag")

	// ignore field
	hook.AddIgnore("context")

	// filter func
	hook.AddFilter("error", logrus_fluent.FilterError)

	logrus.AddHook(hook)
}

func logging(ctx context.Context) {
	logrus.WithFields(logrus.Fields{
		"value":   "some content...",
		"error":   errors.New("unknown error"), // this field will be applied filter function in the hook.
		"context": ctx,                         // this field will be ignored in the hook.
	}).Error("error message")
}
```


## Special fields

Some logrus fields have a special meaning in this hook.

- `tag` is used as a fluentd tag. (if `tag` is omitted, Entry.Message is used as a fluentd tag, unless a static tag is set for the hook with `hook.SetTag`)
