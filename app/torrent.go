package main

import (
	"log"
	"os"
)

type Torrent struct {
	Tracker string
	Length  int
}

func parseTorrentFile(f string) (Torrent, error) {
	t := Torrent{}
	bs, err := os.ReadFile(f)
	if err != nil {
		return t, err
	}
	m, _, err := decodeDict(string(bs))
	if err != nil {
		return t, err
	}
	t.Tracker = m["announce"].(string)
	info := m["info"].(map[string]any)
	if err != nil {
		return t, err
	}
	log.Printf("%s info: %v", f, info)
	t.Length = info["length"].(int)
	return t, nil
}
