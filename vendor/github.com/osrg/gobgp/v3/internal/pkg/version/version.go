// Copyright (C) 2018 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package version

import "fmt"

const MAJOR uint = 3
const MINOR uint = 5
const PATCH uint = 0

var COMMIT string = ""
var IDENTIFIER string = ""
var METADATA string = ""

func Version() string {
	var suffix string = ""
	if len(IDENTIFIER) > 0 {
		suffix = fmt.Sprintf("-%s", IDENTIFIER)
	}

	if len(COMMIT) > 0 || len(METADATA) > 0 {
		suffix = suffix + "+"
	}

	if len(COMMIT) > 0 {
		suffix = fmt.Sprintf("%s"+"commit.%s", suffix, COMMIT)

	}

	if len(METADATA) > 0 {
		if len(COMMIT) > 0 {
			suffix = suffix + "."
		}
		suffix = suffix + METADATA
	}

	return fmt.Sprintf("%d.%d.%d%s", MAJOR, MINOR, PATCH, suffix)
}
