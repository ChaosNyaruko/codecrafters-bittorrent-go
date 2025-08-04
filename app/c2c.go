package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
)

// TODO: randomize it
var myID = strings.Repeat("1234567890", 2)

func handShake(target string, t Torrent) error {
	conn, err := net.Dial("tcp", target)
	if err != nil {
		return fmt.Errorf("dial tcp error: %v", err)
	}
	defer conn.Close()

	pkt := make([]byte, 1+19+8+20+20)
	pkt[0] = 19
	copy(pkt[1:20], "BitTorrent protocol")
	// pkt[20:28] = 0

	copy(pkt[28:48], t.Hash[:])
	copy(pkt[48:68], myID[:])

	n, err := conn.Write(pkt)
	if err != nil {
		return fmt.Errorf("send to %v err: %v", target, err)
	}

	log.Printf("%d bytes sent to %s", n, target)

	resp := &HandShakeMessage{}
	if err := binary.Read(conn, binary.BigEndian, &resp.Length); err != nil {
		return err
	}

	magic := make([]byte, resp.Length)
	if err := binary.Read(conn, binary.BigEndian, magic); err != nil {
		return err
	}

	resp.MagicHeader = string(magic)
	if err := binary.Read(conn, binary.BigEndian, resp.Reserved[:]); err != nil {
		return err
	}
	if err := binary.Read(conn, binary.BigEndian, resp.InfoHash[:]); err != nil {
		return err
	}
	if err := binary.Read(conn, binary.BigEndian, resp.PeerID[:]); err != nil {
		return err
	}

	fmt.Printf("Peer ID: %x\n", resp.PeerID)
	return nil
}

type HandShakeMessage struct {
	Length      uint8
	MagicHeader string
	Reserved    [8]byte
	InfoHash    [20]byte
	PeerID      [20]byte
}
