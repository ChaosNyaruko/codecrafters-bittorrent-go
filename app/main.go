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

func decodeBencode(bencodedString string) (any, error) {
	if unicode.IsDigit(rune(bencodedString[0])) {
		s, _, err := decodeString(bencodedString)
		return s, err
	} else if rune(bencodedString[0]) == 'i' { // i for integer
		i, _, err := decodeInteger(bencodedString)
		return i, err
	} else if rune(bencodedString[0]) == 'l' { // l for list
		str, _, err := decodeList(bencodedString)
		return str, err
	} else {
		return "", fmt.Errorf("Only strings are supported at the moment")
	}
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
	if err != nil {
		return "", -1, fmt.Errorf("decode string %q Atoi lengthStr:%v err: %v", bencodedString, lengthStr, err)
	}

	return bencodedString[firstColonIndex+1 : firstColonIndex+1+length], firstColonIndex + length, nil
}

func decodeList(s string) ([]any, int, error) {
	var i = 0
	log.Printf("decodeList: %v", s)
	if len(s) < 2 {
		return nil, -1, fmt.Errorf("too short bencoded list: %v", s)
	}
	var res []any
	if s[len(s)-1] != 'e' {
		return nil, -1, fmt.Errorf("list not ends with 'e' %v", s)
	}
	i = 1
	for len(s) > 0 {
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
			if len(s) < 1 || s[i] != 'e' {
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
	return n, endAt, nil
}

func main() {
	command := os.Args[1]

	if command == "decode" {
		bencodedValue := os.Args[2]

		decoded, err := decodeBencode(bencodedValue)
		if err != nil {
			fmt.Println(err)
			return
		}

		jsonOutput, _ := json.Marshal(decoded)
		fmt.Println(string(jsonOutput))
	} else {
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}
