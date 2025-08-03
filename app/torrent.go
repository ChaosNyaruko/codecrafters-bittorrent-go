package main

import (
	"crypto/sha1"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
)

type Torrent struct {
	Tracker string
	Length  int
	Hash    [20]byte
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
	log.Printf("%s info: %v", f, info)
	t.Length = info["length"].(int)

	// calc hash
	encInfo, err := encode(info)
	// debugDec, _, err := decode(encInfo)
	// log.Printf("dec [%v] %+v", err, debugDec)
	if err != nil {
		return t, err
	}
	t.Hash = sha1.Sum([]byte(encInfo))
	log.Print(len(t.Hash))

	return t, nil
}

type Item struct {
	Key string
	Val any
}

type ByKey []Item

func (a ByKey) Len() int           { return len(a) }
func (a ByKey) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByKey) Less(i, j int) bool { return a[i].Key < a[j].Key }

func encodeDict(m map[string]any) (string, error) {
	l := make(ByKey, 0, len(m))
	for k, v := range m {
		log.Printf("push: %v, %v", k, v)
		l = append(l, Item{k, v})
	}
	sort.Sort(l)
	log.Printf("sorted dict: %+v", l)
	res := "d"
	for _, item := range l {
		key, err := encode(item.Key)
		if err != nil {
			return res, err
		}
		res += key
		if x, err := encode(item.Val); err != nil {
			return res, err
		} else {
			res += x
		}
	}
	res += "e"
	return res, nil
}

func encodeString(s string) (string, error) {
	return fmt.Sprintf("%d:%s", len(s), s), nil
}

func encodeInt(i int) (string, error) {
	return "i" + strconv.Itoa(i) + "e", nil
}

func encodeList(l []any) (string, error) {
	var res = "l"
	for _, item := range l {
		if x, err := encode(item); err != nil {
			return res, err
		} else {
			res += x
		}
	}
	res += "e"
	return res, nil
}

func encode(item any) (string, error) {
	switch v := item.(type) {
	case int:
		return encodeInt(v)
	case string:
		return encodeString(v)
	case []any:
		return encodeList(v)
	case map[string]any:
		return encodeDict(v)
	default:
		return "", fmt.Errorf("unsupported benencode type: %v, %T, %v, %T", v, v, item, item)
	}
}
