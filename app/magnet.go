package main

import (
	"fmt"
	"net/url"
	"strings"
)

type Magnet struct {
	hash    string
	tracker string
}

func parseMagnet(l string) (Magnet, error) {
	m := Magnet{}
	const scheme = "magnet:?"
	l = strings.TrimSpace(l)
	if !strings.HasPrefix(l, scheme) {
		return m, fmt.Errorf("unrecognized scheme")
	}
	l = l[len(scheme):]
	v, err := url.ParseQuery(l)
	if err != nil {
		return m, err
	}

	xt, ok := v["xt"]
	if !ok {
		return m, fmt.Errorf("xt is required")
	}

	tr, _ := v["tr"]

	hash := xt[0]
	const magic = "urn:btih:"
	if !strings.HasPrefix(hash, magic) {
		return m, fmt.Errorf("bad hash: %v", hash)
	}
	m.hash = hash[len(magic):]
	m.tracker = tr[0]

	return m, nil
}
