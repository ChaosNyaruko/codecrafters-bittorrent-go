package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"unicode"
	// bencode "github.com/jackpal/bencode-go" // Available if you need it!
)

// Ensures gofmt doesn't remove the "os" encoding/json import (feel free to remove this!)
var _ = json.Marshal

func decode(bencodedString string) (any, int, error) {
	if unicode.IsDigit(rune(bencodedString[0])) {
		s, j, err := decodeString(bencodedString)
		return s, j, err
	} else if rune(bencodedString[0]) == 'i' { // i for integer
		i, j, err := decodeInteger(bencodedString)
		return i, j, err
	} else if rune(bencodedString[0]) == 'l' { // l for list
		str, j, err := decodeList(bencodedString)
		return str, j, err
	} else if bencodedString[0] == 'd' { // d for dictionary
		m, j, err := decodeDict(bencodedString)
		return m, j, err
	} else {
		return "", -1, fmt.Errorf("Only strings are supported at the moment")
	}
}

func decodeBencode(bencodedString string) (any, error) {
	res, _, err := decode(bencodedString)
	return res, err
}

// Example:
// - 5:hello -> hello
// - 10:hello12345 -> hello12345
func decodeString(bencodedString string) (string, int, error) {
	log.Printf("decodeString: %v", bencodedString)
	var firstColonIndex int

	for i := 0; i < len(bencodedString); i++ {
		if bencodedString[i] == ':' {
			firstColonIndex = i
			break
		}
	}

	lengthStr := bencodedString[:firstColonIndex]

	length, err := strconv.Atoi(lengthStr)
	log.Printf("decode string: %q, %s, %d", bencodedString, lengthStr, length)
	if err != nil {
		return "", -1, fmt.Errorf("decode string %q Atoi lengthStr:%v err: %v", bencodedString, lengthStr, err)
	}
	if firstColonIndex+1+length > len(bencodedString) {
		return "", -1, fmt.Errorf("too short string for %q/[%d, %d]", bencodedString, firstColonIndex+1, length)
	}

	return bencodedString[firstColonIndex+1 : firstColonIndex+1+length], firstColonIndex + length, nil
}

func decodeDict(s string) (map[string]any, int, error) {
	var i = 0
	log.Printf("decodeDict %v", s)
	if len(s) < 2 {
		return nil, -1, fmt.Errorf("too short bencoded dict: %v", s)
	}
	var res = make(map[string]any)
	if s[0] != 'd' {
		return nil, -1, fmt.Errorf("dict should start with 'd', %q", s)
	}
	i += 1 // eat 'd'
	for i < len(s) {
		log.Printf("dict: %v", s[i:])
		switch {
		case unicode.IsDigit(rune(s[i])):
			key, j, err := decodeString(s[i:])
			if err != nil {
				return nil, -1, fmt.Errorf("decode key err: %v, %q", err, s[i:])
			}
			i += j + 1
			value, j, err := decode(s[i:])
			if err != nil {
				return nil, -1, fmt.Errorf("decode value err: %v, %q", err, s[i:])
			}
			i += j + 1
			res[key] = value
		default:
			if i >= len(s) || s[i] != 'e' {
				return res, i, fmt.Errorf("invalid dict, should end with 'e': %s", s[i:])
			}
			return res, i, nil
		}
	}
	return res, len(s), nil
}

func decodeList(s string) ([]any, int, error) {
	var i = 0
	log.Printf("decodeList: %v", s)
	if len(s) < 2 {
		return nil, -1, fmt.Errorf("too short bencoded list: %v", s)
	}
	var res = []any{}
	i = 1
	for i < len(s) {
		switch {
		case s[i] == 'i':
			if n, j, err := decodeInteger(s[i:]); err != nil {
				return nil, -1, err
			} else {
				res = append(res, n)
				i += j + 1
				log.Printf("add %v, remain: %v", n, s[i:])
			}
		case s[i] == 'l':
			if list, j, err := decodeList(s[i:]); err != nil {
				return nil, -1, err
			} else {
				res = append(res, list)
				i += j + 1
				log.Printf("add %v, remain: %v", list, s[i:])
			}
		case unicode.IsDigit(rune(s[i])):
			if str, j, err := decodeString(s[i:]); err != nil {
				return nil, -1, err
			} else {
				res = append(res, str)
				i += j + 1
				log.Printf("add %v, remain: %v", str, s[i:])
			}
		default:
			if i >= len(s) || s[i] != 'e' {
				return res, i, fmt.Errorf("invalid list, should end with 'e': %s", s[i:])
			}
			return res, i, nil
		}
	}
	return res, len(s), nil
}

func decodeInteger(s string) (int, int, error) {
	log.Printf("decodeInteger: %v", s)
	endAt := -1
	for i := 1; i < len(s); i++ {
		if s[i] == 'e' {
			endAt = i
			break
		}
	}
	if endAt == -1 {
		return 0, -1, fmt.Errorf("integer should end with e: %v", s)
	}
	number := s[1:endAt]
	n, err := strconv.Atoi(number)
	if err != nil {
		return 0, -1, fmt.Errorf("bad number strings: %v", number)
	}
	log.Printf("decoded integer: %s", number)
	return n, endAt, nil
}

func main() {
	command := os.Args[1]

	switch command {
	case "decode":
		bencodedValue := os.Args[2]
		decoded, err := decodeBencode(bencodedValue)
		if err != nil {
			fmt.Println(err)
			return
		}

		jsonOutput, _ := json.Marshal(decoded)
		fmt.Println(string(jsonOutput))
	case "info":
		torrent := os.Args[2]
		t, err := parseTorrentFile(torrent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse torrent file [%v] error: %v", torrent, err)
		}
		fmt.Printf("Tracker URL: %s\nLength: %d\n", t.Tracker, t.Length)
	default:
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}
