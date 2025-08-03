package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_encode(t *testing.T) {
	info := map[string]any{"string": "john", "int": 32, "list": []any{1, "xx"}, "dict": map[string]any{"nested": 112233}}
	s, err := encode(info)
	assert.Nil(t, err)
	assert.Equal(t, "d4:dictd6:nestedi112233ee3:inti32e4:listli1e2:xxe6:string4:johne", s)
}
