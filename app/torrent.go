package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
)

type Torrent struct {
	Tracker     string
	Length      int
	Hash        [20]byte
	PieceLength int
	PieceHashes []string
}

func parseTorrentFile(f string) (Torrent, error) {
	t := Torrent{}
	t.PieceHashes = make([]string, 0)
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

	t.PieceLength = info["piece length"].(int)
	hashes := []byte(info["pieces"].(string))
	if len(hashes)%20 != 0 {
		return t, fmt.Errorf("concatenated pieces length should be multiples of 20")
	}
	for i := 0; i < len(hashes); i += 20 {
		h := hashes[i : i+20]
		t.PieceHashes = append(t.PieceHashes, hex.EncodeToString(h))
	}

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

type Target struct {
	IP   net.IP
	Port uint16
}

func (p Target) String() string {
	return fmt.Sprintf("%s:%d", p.IP, p.Port)
}

func getPeersFromTracker(t Torrent) ([]Target, error) {
	tracker := t.Tracker
	params := url.Values{}

	params.Set("info_hash", string(t.Hash[:]))
	params.Set("peer_id", myID)
	params.Set("port", "6881")
	params.Set("uploaded", "0")
	params.Set("downloaded", "0")
	params.Set("left", strconv.Itoa(t.Length))
	params.Set("compact", "1")
	queryString := params.Encode()

	full := tracker + "?" + queryString
	log.Printf("GET from %q", full)

	resp, err := http.Get(full)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	s := string(body)
	log.Print(s)

	ps, _, err := decode(s)
	if err != nil {
		return nil, fmt.Errorf("bad resp from Tracker: %q", s)
	}

	var res = make([]Target, 0)

	info := ps.(map[string]any)
	interval := info["interval"].(int)

	peers := info["peers"].(string)
	log.Printf("interval: %d, peers: %v/%d/%d", interval, peers, len(peers), len([]byte(peers)))

	addrs := []byte(peers)

	if len(addrs)%6 != 0 { // TODO: ipv6?
		return nil, fmt.Errorf("peers len should be multiples of 6, but got %d", len(addrs))
	}

	for i := 0; i < len(addrs); i += 6 {
		ip := addrs[i : i+4]
		port := addrs[i+4 : i+6]
		p := Target{
			IP:   ip,
			Port: uint16(port[0])*256 + uint16(port[1]),
		}
		res = append(res, p)
	}

	return res, nil
}
