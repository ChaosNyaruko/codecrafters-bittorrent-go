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

func Test_decode(t *testing.T) {
	s := "d8:completei5e10:incompletei0e8:intervali60e12:min intervali60ee"
	// s := "d8:completei3e10:incompletei0e8:intervali60e12:min intervali60e5:peers18:G6-;6#e"
	m, err := decodeBencode(s)
	assert.Nil(t, err)
	t.Logf("ded: %+v", m)
}
