package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"strings"
)

// TODO: randomize it
var myID = strings.Repeat("1234567890", 2)

func handShake(target string, t Torrent) (*Client, error) {
	c := &Client{
		t:      t,
		target: target,
	}
	return c, c.handShake(target)
}

type HandShakeMessage struct {
	Length      uint8
	MagicHeader string
	Reserved    [8]byte
	InfoHash    [20]byte
	PeerID      [20]byte
}

type Client struct {
	mainConn net.Conn
	target   string
	t        Torrent
}

type PeerMessage struct {
	Length  uint32
	MsgID   uint8
	Payload []byte
}

func (msg PeerMessage) String() string {
	return fmt.Sprintf("Length: %d, MsgID: %d", msg.Length, msg.MsgID)
}

func (msg *PeerMessage) Pack() []byte {
	msg.Length = uint32(len(msg.Payload)) + 1
	buf := make([]byte, 0, 4+msg.Length)
	buf = binary.BigEndian.AppendUint32(buf, msg.Length)
	buf = append(buf, msg.MsgID)
	buf = append(buf, msg.Payload...)
	return buf
}

func (msg *PeerMessage) Unpack(r io.Reader) error {
	if err := binary.Read(r, binary.BigEndian, &msg.Length); err != nil {
		return err
	}
	log.Printf("read msg len: %d", msg.Length)
	if err := binary.Read(r, binary.BigEndian, &msg.MsgID); err != nil {
		return err
	}
	log.Printf("read msg id: %d", msg.MsgID)
	body := make([]byte, msg.Length-1)
	if err := binary.Read(r, binary.BigEndian, &body); err != nil {
		return err
	}
	log.Printf("read msg body: %d", len(msg.Payload))
	msg.Payload = body
	return nil
}

const (
	choke = iota
	unchoke
	interested
	notInterested
	have
	bitfield
	request
	piece
	cancel
)

func (c *Client) downloadPiece(pIdx int, fname string) ([]byte, error) {
	msg := PeerMessage{}
	for {
		log.Printf("waiting for bitfield")
		if err := msg.Unpack(c.mainConn); err != nil {
			return nil, err
		}
		log.Printf("peer msg: %s", msg)

		if msg.MsgID == bitfield {
			// You can read and ignore the payload for now, the tracker we use for this challenge ensures that all peers have all pieces available.
			break
		}
	}

	msg.MsgID = interested
	msg.Payload = nil
	pkt := msg.Pack()

	n, err := c.mainConn.Write(pkt)
	if err != nil {
		return nil, err
	}
	log.Printf("send interested msg: %d", n)

	for {
		if err := msg.Unpack(c.mainConn); err != nil {
			return nil, err
		}
		log.Printf("peer msg: %+v", msg)

		if msg.MsgID == unchoke {
			// empty payload
			log.Printf("unchoke recevied")
			break
		}
	}

	msg.Payload = nil
	// TODO: concurrency
	pieceData := make([]byte, 0, c.t.PieceLength)
	blkCnt := int(math.Ceil(float64(c.t.PieceLength) / float64(blockSize)))
	log.Printf("piece size: %d, blksize: %d, blkcnt: %d", c.t.PieceLength, blockSize, blkCnt)
	for blkId := range blkCnt {
		msg.MsgID = request
		msg.Payload = nil
		msg.Payload = binary.BigEndian.AppendUint32(msg.Payload, uint32(pIdx))
		msg.Payload = binary.BigEndian.AppendUint32(msg.Payload, uint32(blkId*blockSize))
		size := blockSize
		if blkId == blkCnt-1 {
			size = c.t.PieceLength - blkId*blockSize
		}
		msg.Payload = binary.BigEndian.AppendUint32(msg.Payload, uint32(size))
		pkt = msg.Pack()
		n, err := c.mainConn.Write(pkt)
		if err != nil {
			return nil, err
		}
		log.Printf("send request msg [%d:%d/%d]: %d, pkt: %v", pIdx, blkId, blkCnt, n, pkt)

		for {
			if err := msg.Unpack(c.mainConn); err != nil {
				return nil, err
			}
			log.Printf("peer msg: %+v", msg)

			if msg.MsgID == piece {
				log.Printf("recevied piece[%d vs %d], begin: %d(%d), block_len:%d",
					pIdx, binary.BigEndian.Uint32(msg.Payload[:4]),
					binary.BigEndian.Uint32(msg.Payload[4:8]), blkId,
					len(msg.Payload[8:]))
				pieceData = append(pieceData, msg.Payload[8:]...)
				break
			}
		}

	}

	fd, err := os.Create(fname)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	wn, err := fd.Write(pieceData)
	if err != nil {
		return pieceData, nil
	}
	log.Printf("write to %s success: %d/%d/%d", fname, wn, len(pieceData), c.t.PieceLength)

	return pieceData, nil
}

const blockSize = 16 * 1024

func (c *Client) Close() error {
	if c.mainConn != nil {
		return c.mainConn.Close()
	}
	return nil
}

func (c *Client) handShake(target string) error {
	conn, err := net.Dial("tcp", target)
	if err != nil {
		return fmt.Errorf("dial tcp error: %v", err)
	}
	c.mainConn = conn

	pkt := make([]byte, 1+19+8+20+20)
	pkt[0] = 19
	copy(pkt[1:20], "BitTorrent protocol")
	// pkt[20:28] = 0

	copy(pkt[28:48], c.t.Hash[:])
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
