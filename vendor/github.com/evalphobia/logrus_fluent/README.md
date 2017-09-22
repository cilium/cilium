Fluentd Hook for Logrus <img src="http://i.imgur.com/hTeVwmJ.png" width="40" height="40" alt=":walrus:" class="emoji" title=":walrus:"/>
----

[![GoDoc][1]][2] [![License: Apache 2.0][3]][4] [![Release][5]][6] [![Travis Status][7]][8] [![wercker Status][19]][20] [![Coveralls Coverage][9]][10] [![Go Report Card][13]][14] [![Downloads][15]][16]

[1]: https://godoc.org/github.com/evalphobia/logrus_fluent?status.svg
[2]: https://godoc.org/github.com/evalphobia/logrus_fluent
[3]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[4]: LICENSE.md
[5]: https://img.shields.io/github/release/evalphobia/logrus_fluent.svg
[6]: https://github.com/evalphobia/logrus_fluent/releases/latest
[7]: https://travis-ci.org/evalphobia/logrus_fluent.svg?branch=master
[8]: https://travis-ci.org/evalphobia/logrus_fluent
[9]: https://coveralls.io/repos/evalphobia/logrus_fluent/badge.svg?branch=master&service=github
[10]: https://coveralls.io/github/evalphobia/logrus_fluent?branch=master
[11]: https://codecov.io/github/evalphobia/logrus_fluent/coverage.svg?branch=master
[12]: https://codecov.io/github/evalphobia/logrus_fluent?branch=master
[13]: https://goreportcard.com/badge/github.com/evalphobia/logrus_fluent
[14]: https://goreportcard.com/report/github.com/evalphobia/logrus_fluent
[15]: https://img.shields.io/github/downloads/evalphobia/logrus_fluent/total.svg?maxAge=1800
[16]: https://github.com/evalphobia/logrus_fluent/releases
[17]: https://img.shields.io/github/stars/evalphobia/logrus_fluent.svg
[18]: https://github.com/evalphobia/logrus_fluent/stargazers
[19]: https://app.wercker.com/status/04fb4bde79d8c54bb681af664394d2e4/s/master
[20]: https://app.wercker.com/project/byKey/04fb4bde79d8c54bb681af664394d2e4


## Usage

```go
import (
	"github.com/sirupsen/logrus"
	"github.com/evalphobia/logrus_fluent"
)

func main() {
	hook, err := logrus_fluent.NewWithConfig(logrus_fluent.Config{
		Host: "localhost",
		Port: 24224,
	})
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
