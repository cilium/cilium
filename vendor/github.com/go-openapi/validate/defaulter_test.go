package validate

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-openapi/spec"
	"github.com/go-openapi/strfmt"
)

var defaulterFixturesPath = filepath.Join("fixtures", "defaulting")

func TestDefaulter(t *testing.T) {
	fname := filepath.Join(defaulterFixturesPath, "schema.json")
	b, err := ioutil.ReadFile(fname)
	assert.NoError(t, err)
	var schema spec.Schema
	assert.NoError(t, json.Unmarshal(b, &schema))

	err = spec.ExpandSchema(&schema, nil, nil /*new(noopResCache)*/)
	assert.NoError(t, err, fname+" should expand cleanly")

	validator := NewSchemaValidator(&schema, nil, "", strfmt.Default)
	x := map[string]interface{}{
		"nested": map[string]interface{}{},
		"all":    map[string]interface{}{},
		"any":    map[string]interface{}{},
		"one":    map[string]interface{}{},
	}
	t.Logf("Before: %v", x)
	r := validator.Validate(x)
	assert.False(t, r.HasErrors(), fmt.Sprintf("unexpected validation error: %v", r.AsError()))

	r.ApplyDefaults()
	t.Logf("After: %v", x)
	var expected interface{}
	err = json.Unmarshal([]byte(`{
		"int": 42,
		"str": "Hello",
		"obj": {"foo": "bar"},
		"nested": {"inner": 7},
		"all": {"foo": 42, "bar": 42},
		"any": {"foo": 42},
		"one": {"bar": 42}
	}`), &expected)
	assert.NoError(t, err)
	assert.Equal(t, expected, x)
}
