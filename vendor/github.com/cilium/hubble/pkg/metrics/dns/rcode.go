// Copyright 2019 Authors of Hubble
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

package dns

var rcodeNames = map[uint32]string{
	0:  "No Error",
	1:  "Format Error",
	2:  "Server Failure",
	3:  "Non-Existent Domain",
	4:  "Not Implemented",
	5:  "Query Refused",
	6:  "Name Exists when it should not",
	7:  "RR Set Exists when it should not",
	8:  "RR Set that should exist does not",
	9:  "Not Authorized",
	10: "Name not contained in zone",
	11: "DSO-TYPE Not Implemented",
	16: "Bad OPT Version",
	17: "Key not recognized",
	18: "Signature out of time window",
	19: "Bad TKEY Mode",
	20: "Duplicate key name",
	21: "Algorithm not supported",
	22: "Bad Truncation",
	23: "Bad/missing Server Cookie",
}
