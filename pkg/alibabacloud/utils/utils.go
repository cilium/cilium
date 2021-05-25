// Copyright 2021 Authors of Cilium
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

package utils

import (
	"strconv"

	log "github.com/sirupsen/logrus"
)

const eniIndexTagKey = "cilium-eni-index"

// GetENIIndexFromTags get ENI index from tags
func GetENIIndexFromTags(tags map[string]string) int {
	v, ok := tags[eniIndexTagKey]
	if !ok {
		return 0
	}
	index, err := strconv.Atoi(v)
	if err != nil {
		log.WithError(err).Warning("Unable to retrieve index from ENI")
	}
	return index
}

// FillTagWithENIIndex set the index to tags
func FillTagWithENIIndex(tags map[string]string, index int) map[string]string {
	tags[eniIndexTagKey] = strconv.Itoa(index)
	return tags
}
