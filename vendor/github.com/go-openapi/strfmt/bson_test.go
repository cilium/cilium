// Copyright 2015 go-swagger maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package strfmt

import (
	"testing"

	"gopkg.in/mgo.v2/bson"

	"github.com/stretchr/testify/assert"
)

func TestBSONObjectId_fullCycle(t *testing.T) {
	id := NewObjectId("507f1f77bcf86cd799439011")
	bytes, err := id.MarshalText()
	assert.NoError(t, err)

	var idCopy ObjectId

	err = idCopy.Scan(bytes)
	assert.NoError(t, err)
	assert.Equal(t, id, idCopy)

	err = idCopy.UnmarshalText(bytes)
	assert.NoError(t, err)
	assert.Equal(t, id, idCopy)

	jsonBytes, err := id.MarshalJSON()
	assert.NoError(t, err)

	err = idCopy.UnmarshalJSON(jsonBytes)
	assert.NoError(t, err)
	assert.Equal(t, id, idCopy)

	bsonBytes, err := bson.Marshal(&id)
	assert.NoError(t, err)

	err = bson.Unmarshal(bsonBytes, &idCopy)
	assert.NoError(t, err)
	assert.Equal(t, id, idCopy)
}
