package logrus_fluent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type Creature struct {
	Name   string
	Human  bool
	Height int
	Weight int
	Alias  string `fluent:"nickname"`
}

func TestConvertToValueStruct(t *testing.T) {
	assert := assert.New(t)

	v := Creature{
		Name:   "cat",
		Height: 50,
		Weight: 4,
		Alias:  "tama",
	}
	result := ConvertToValue(v, TagName)

	r, ok := result.(map[string]interface{})
	assert.True(ok)
	assert.Equal(v.Name, r["Name"])
	assert.Equal(v.Height, r["Height"])
	assert.Equal(v.Weight, r["Weight"])
	assert.Equal(v.Alias, r["nickname"])
	assert.Equal(v.Human, r["Human"])
}

func TestConvertToValueSlice(t *testing.T) {
	assert := assert.New(t)

	var list []*Creature
	list = append(list, &Creature{Name: "cat"})
	list = append(list, &Creature{Name: "dog"})
	list = append(list, nil)
	list = append(list, &Creature{Name: "bird"})

	result := ConvertToValue(list, TagName)
	r, ok := result.([]interface{})
	assert.True(ok)
	assert.Len(r, 4)
}

func TestConvertToValueNil(t *testing.T) {
	assert := assert.New(t)
	result := ConvertToValue(nil, TagName)
	assert.Equal(nil, result)

	var ptr *Creature
	result = ConvertToValue(ptr, TagName)
	assert.Equal(nil, result)
}
