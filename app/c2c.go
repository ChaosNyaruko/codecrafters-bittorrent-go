package main

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
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

type HandShakeMessage struct {
	Length      uint8
	MagicHeader string
	Reserved    [8]byte
	InfoHash    [20]byte
	PeerID      [20]byte
}

type Client struct {
	mainConn net.Conn
	targets  []Target
	t        Torrent
}

type Peer struct {
	addr string
	conn net.Conn
	id   [20]byte
}

func (p *Peer) Close() {
	log.Printf("close peer: %v", p.id)
	p.conn.Close()
}

func (p *Peer) readMsg() (*PeerMessage, error) {
	msg := &PeerMessage{}
	if err := msg.Unpack(p.conn); err != nil {
		return nil, err
	}
	return msg, nil
}

func (p *Peer) downloadBlk(task blockTask) ([]byte, error) {
	pIdx, pLen, blkId := task.pIdx, task.pLen, task.idx
	pkt := requestPkt(pIdx, blkId, pLen)
	_, err := p.conn.Write(pkt)
	if err != nil {
		return nil, err
	}
	log.Printf("try donwloading %+v", task)
	for {
		msg, err := p.readMsg()
		if err == io.EOF {
			log.Printf("[request]connection closed: %v->%v", p.conn.LocalAddr(), p.conn.RemoteAddr())
			return nil, err
		}
		if err != nil {
			log.Printf("readMsg err: %v", err)
			continue
		}
		switch msg.MsgID {
		case piece:
			log.Printf("recevied piece[%d vs %d], begin: %d(%d), block_len:%d",
				pIdx, binary.BigEndian.Uint32(msg.Payload[:4]),
				binary.BigEndian.Uint32(msg.Payload[4:8]), blkId,
				len(msg.Payload[8:]))
			return msg.Payload[8:], nil
		case choke:
			return nil, fmt.Errorf("choked by %v", p.addr)
		default:
		}
	}
}

func (p *Peer) connect(hash []byte) error {
	err := p.handshake(hash)
	log.Printf("connecting %v->%v, err: %v", p.conn.LocalAddr(), p.conn.RemoteAddr, err)
	if err != nil {
		p.Close()
		return err
	}

	for {
		msg, err := p.readMsg()
		if err == io.EOF {
			log.Printf("[connect]connection closed: %v->%v", p.conn.LocalAddr(), p.conn.RemoteAddr())
			return err
		}
		if err != nil {
			continue
		}
		if msg.MsgID == bitfield {
			// You can read and ignore the payload for now, the tracker we use for this challenge ensures that all peers have all pieces available.
			break
		} else {
			log.Printf("recevied %v when expecting bitfield", msg.MsgID)
		}
	}

	pkt := interestedPkt()

	_, err = p.conn.Write(pkt)
	if err != nil {
		return err
	}

	for {
		msg, err := p.readMsg()
		if err != nil {
			return err
		}

		if msg.MsgID == unchoke {
			// empty payload
			log.Printf("unchoke recevied")
			break
		} else {
			log.Printf("recevied %v when expecting unchoke", msg.MsgID)
		}
	}

	return nil
}

func (p *Peer) handshake(hash []byte) error {
	conn, err := net.Dial("tcp", p.addr)
	if err != nil {
		return fmt.Errorf("dial tcp error: %v", err)
	}
	p.conn = conn

	pkt := handshakePkt(hash[:])
	_, err = conn.Write(pkt)
	if err != nil {
		return fmt.Errorf("send to %v err: %v", p.addr, err)
	}

	resp := &HandShakeMessage{}
	if err := binary.Read(conn, binary.BigEndian, &resp.Length); err != nil {
		return err
	}

	magic := make([]byte, resp.Length)
	if err := binary.Read(conn, binary.BigEndian, magic); err != nil {
		return err
	}

	// resp.MagicHeader = string(magic)
	if err := binary.Read(conn, binary.BigEndian, resp.Reserved[:]); err != nil {
		return err
	}
	if err := binary.Read(conn, binary.BigEndian, resp.InfoHash[:]); err != nil {
		return err
	}
	if err := binary.Read(conn, binary.BigEndian, resp.PeerID[:]); err != nil {
		return err
	}

	copy(p.id[:], resp.PeerID[:])

	return nil
}

type PeerPool struct {
	available chan *Peer
	pending   chan *Peer
	hash      []byte
	close     chan int
}

func (pp *PeerPool) clean() error {
	close(pp.pending)
	close(pp.available)
	for p := range pp.pending {
		p.Close()
	}
	for p := range pp.available {
		p.Close()
	}
	log.Printf("peer pool stopped")
	return nil
}

func (pp *PeerPool) run() error {
	go func() {
		for p := range pp.pending {
			if err := p.connect(pp.hash); err != nil {
				p.Close()
				pp.pending <- p
			} else {
				pp.available <- p
			}
		}
	}()

	<-pp.close
	err := pp.clean()
	log.Printf("cleanup PeerPool")
	return err
}

type PieceDownloader struct {
	pp          *PeerPool
	piece       []byte
	t           Torrent
	idx         int // piece idx
	pendindTask chan blockTask
	done        chan int
}

type blockTask struct {
	idx  int
	cnt  int
	pIdx int
	pLen int
}

func (pd *PieceDownloader) run() error {
	blkCnt := int(math.Ceil(float64(pd.t.PieceLength) / float64(blockSize)))
	pd.pendindTask = make(chan blockTask, blkCnt)
	pd.done = make(chan int)
	pd.piece = make([]byte, pd.t.PieceLength)

	for i := range 5 {
		go func() {
			log.Printf("downloader %d started...", i)
			defer log.Printf("downloader %d stopped...", i)
			for b := range pd.pendindTask {
				p := <-pd.pp.available
				if blk, err := p.downloadBlk(b); err != nil {
					p.Close()
					pd.pp.pending <- p
					pd.pendindTask <- b
				} else {
					l := b.idx * blockSize
					size := blockSize
					if b.idx == blkCnt-1 {
						size = pd.t.PieceLength - b.idx*blockSize
					}
					if size != len(blk) {
						log.Fatalf("??? size: %d, len(blk): %d", size, blk)
					}
					copy(pd.piece[l:l+size], blk)
					log.Printf("blk %v/%v finished, [%v:%v]", b.idx, blkCnt, l, l+size)
					pd.pp.available <- p
					pd.done <- 1
				}
			}
		}()
	}

	for i := range blkCnt {
		pd.pendindTask <- blockTask{
			idx:  i,
			cnt:  blkCnt,
			pIdx: pd.idx,
			pLen: pd.t.PieceLength,
		}
	}

	doneCnt := 0
	for d := range pd.done {
		doneCnt += d
		log.Printf("blk tasks finished: %d/%d", doneCnt, blkCnt)
		if doneCnt == blkCnt {
			break
		}
	}
	close(pd.done)
	close(pd.pendindTask)
	log.Printf("piece downloader stopped: %v/%v", len(pd.piece), pd.t.PieceLength)

	h := sha1.Sum(pd.piece)
	got := hex.EncodeToString(h[:])
	expected := pd.t.PieceHashes[pd.idx]
	if got != expected {
		return fmt.Errorf("sha1 checksum not match: \n%v\n%v\n", got, expected)
	}
	return nil
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
		return fmt.Errorf("unpack length: %v", err)
	}
	if err := binary.Read(r, binary.BigEndian, &msg.MsgID); err != nil {
		return fmt.Errorf("unpack msgid: %v", err)
	}
	body := make([]byte, msg.Length-1)
	if err := binary.Read(r, binary.BigEndian, &body); err != nil {
		return fmt.Errorf("unpack body: %v", err)
	}
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
	pp := PeerPool{
		available: make(chan *Peer, 100),
		pending:   make(chan *Peer, 100),
		close:     make(chan int),
		hash:      c.t.Hash[:],
	}

	go func() {
		for j := range len(c.targets) {
			for range 5 {
				p := &Peer{
					addr: c.targets[j].String(),
					conn: nil,
					id:   [20]byte{},
				}
				pp.pending <- p
			}
		}
	}()

	pd := PieceDownloader{
		pp:    &pp,
		piece: make([]byte, 0, c.t.PieceLength),
		t:     c.t,
		idx:   pIdx,
	}
	go pp.run()

	defer func() { pp.close <- 1 }()

	if err := pd.run(); err != nil {
		return nil, err
	}

	pieceData := pd.piece

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

// TODO: duplicate code
func (c *Client) handShake(target string) error {
	conn, err := net.Dial("tcp", target)
	if err != nil {
		return fmt.Errorf("dial tcp error: %v", err)
	}
	c.mainConn = conn

	pkt := handshakePkt(c.t.Hash[:])
	_, err = conn.Write(pkt)
	if err != nil {
		return fmt.Errorf("send to %v err: %v", target, err)
	}

	resp := &HandShakeMessage{}
	if err := binary.Read(conn, binary.BigEndian, &resp.Length); err != nil {
		return err
	}

	magic := make([]byte, resp.Length)
	if err := binary.Read(conn, binary.BigEndian, magic); err != nil {
		return err
	}

	// resp.MagicHeader = string(magic)
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
