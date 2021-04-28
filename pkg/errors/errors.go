// Copyright 2016-2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package errors

import (
	"errors"

	"github.com/sirupsen/logrus"
)

type ErrorWithLogFields struct {
	Err       error
	LogFields logrus.Fields
}

func (e *ErrorWithLogFields) EnrichLogger(l *logrus.Entry) *logrus.Entry {
	return l.WithFields(e.LogFields)
}

func (e *ErrorWithLogFields) Error() string {
	return e.Unwrap().Error()
}

func (e *ErrorWithLogFields) Unwrap() error {
	return e.Err
}

func EnrichLogger(l *logrus.Entry, err error) *logrus.Entry {
	var e *ErrorWithLogFields
	if errors.As(err, &e) {
		return e.EnrichLogger(l).WithError(e.Unwrap())
	}
	return l.WithError(err)
}
