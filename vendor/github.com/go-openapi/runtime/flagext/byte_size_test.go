package flagext

import "testing"
import "github.com/stretchr/testify/assert"

func TestMarshalBytesize(t *testing.T) {
	v, err := ByteSize(1024).MarshalFlag()
	if assert.NoError(t, err) {
		assert.Equal(t, "1.024kB", v)
	}
}

func TestStringBytesize(t *testing.T) {
	v := ByteSize(2048).String()
	assert.Equal(t, "2.048kB", v)
}

func TestUnmarshalBytesize(t *testing.T) {
	var b ByteSize
	err := b.UnmarshalFlag("notASize")
	assert.Error(t, err)

	err = b.UnmarshalFlag("1MB")
	if assert.NoError(t, err) {
		assert.Equal(t, ByteSize(1000000), b)
	}
}

func TestSetBytesize(t *testing.T) {
	var b ByteSize
	err := b.Set("notASize")
	assert.Error(t, err)

	err = b.Set("2MB")
	if assert.NoError(t, err) {
		assert.Equal(t, ByteSize(2000000), b)
	}
}

func TestTypeBytesize(t *testing.T) {
	var b ByteSize
	assert.Equal(t, "byte-size", b.Type())
}
