package lints

/*
 * ZLint Copyright 2018 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

// Contains resources necessary to the Unit Test Cases

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/zmap/zcrypto/x509"
)

func ReadCertificate(inPath string) *x509.Certificate {
	// All of this can be encapsulated in a function
	data, err := ioutil.ReadFile(inPath)
	if err != nil {
		//read failure, die horribly here
		fmt.Println(err)
		panic("File read failed!")
	}
	var textData string = string(data)
	if strings.Contains(textData, "-BEGIN CERTIFICATE-") {
		block, _ := pem.Decode(data)
		if block == nil {
			panic("PEM decode failed!")
		}
		data = block.Bytes
	}
	theCert, err := x509.ParseCertificate(data)
	if err != nil {
		//die horribly here
		fmt.Println(err)
		return nil
	}
	return theCert
}
