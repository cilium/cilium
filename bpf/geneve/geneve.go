// Copyright 2016-2017 Authors of Cilium
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

package geneve

import (
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
)

type GeneveTlv struct {
	optClass uint16
	optType  uint8
	optLen   uint8
	optData  []byte
}

func ValidateOpt(geneveTlv GeneveTlv) bool {
	sz := geneveTlv.optLen
	if sz > 124 || sz%4 != 0 || int(sz) != len(geneveTlv.optData) {
		return false
	}
	return true
}

func ReadOpts(filePath string) (geneveOpts []GeneveTlv, rawData []byte, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening %s: %v", filePath, err)
	}

	reader := csv.NewReader(file)
	reader.Comma = ';'
	tlvCount := 0
	var geneveTlv GeneveTlv
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("error reading Geneve TLVs from file %s: %v", filePath, err)
		}
		val, _ := strconv.ParseUint(record[0], 0, 16)
		geneveTlv.optClass = uint16(val)
		rawData = append(rawData, byte(geneveTlv.optClass>>8))
		rawData = append(rawData, byte(geneveTlv.optClass))

		val, _ = strconv.ParseUint(record[1], 0, 8)
		geneveTlv.optType = uint8(val)
		rawData = append(rawData, geneveTlv.optType)

		val, _ = strconv.ParseUint(record[2], 0, 8)
		geneveTlv.optLen = uint8(val)
		rawData = append(rawData, geneveTlv.optLen>>2)

		geneveTlv.optData, _ = hex.DecodeString(record[3])
		geneveOpts = append(geneveOpts, geneveTlv)
		rawData = append(rawData, geneveTlv.optData...)

		if ValidateOpt(geneveTlv) == false {
			return nil, nil, fmt.Errorf("Geneve tlv %d validation failed %x %x %x", tlvCount, geneveTlv.optClass, geneveTlv.optType, geneveTlv.optLen)
		}

		tlvCount += 1
	}
	return geneveOpts, rawData, nil
}

func WriteOpts(filePath string, c string, t string, l string, v string) error {
	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		return fmt.Errorf("error opening %s: %v", filePath, err)
	}
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("%s;%s;%s;%s\n", c, t, l, v))
	if err != nil {
		return fmt.Errorf("error writing GeneveOpt %s;%s;%s;%s", c, t, l, v)
	}

	return nil
}

func ShowOpts(geneveOpts []GeneveTlv) {
	for i := 0; i < len(geneveOpts); i++ {
		geneveTlv := geneveOpts[i]
		fmt.Println("tlv", i, "fields")
		fmt.Println(geneveTlv.optClass)
		fmt.Println(geneveTlv.optType)
		fmt.Println(geneveTlv.optLen)
		for j := 0; j < len(geneveTlv.optData); j++ {
			fmt.Printf("%x ", geneveTlv.optData[j])
		}
		fmt.Println()
	}
}
