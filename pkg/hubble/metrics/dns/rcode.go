// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

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
