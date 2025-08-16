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
	"strings"
)

const (
	workingThreads = 1
	connPerTarget  = 1
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
	addr             string
	conn             net.Conn
	unchoked         bool
	id               [20]byte
	supportExtension bool
	extensions       map[string]any
	magnetMeta       *MagnetMeta
}

func (p *Peer) Close() {
	log.Printf("close peer: %v", p.id)
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
}

func (p *Peer) readMsg(name string) (*PeerMessage, error) {
	msg := &PeerMessage{}
	if err := msg.Unpack(name, p.conn); err != nil {
		return nil, err
	}
	return msg, nil
}

func (p *Peer) downloadBlk(task blockTask) ([]byte, error) {
	if !p.unchoked {
		pkt := interestedPkt()

		_, err := p.conn.Write(pkt)
		if err != nil {
			return nil, err
		}

		for {
			msg, err := p.readMsg("unchoke")
			if err != nil {
				return nil, err
			}

			if msg.MsgID == unchoke {
				// empty payload
				log.Printf("unchoke recevied")
				break
			} else {
				log.Printf("recevied %v when expecting unchoke", msg.MsgID)
			}
		}
		p.unchoked = true
	}
	pIdx, pLen, blkId := task.pIdx, task.pLen, task.idx
	pkt := requestPkt(pIdx, blkId, pLen)
	_, err := p.conn.Write(pkt)
	if err != nil {
		return nil, err
	}
	log.Printf("try donwloading %+v", task)
	for {
		log.Printf("trying reading 'piece' from %s", p.conn.RemoteAddr())
		msg, err := p.readMsg("piece")
		if err == io.EOF {
			log.Printf("[request]connection closed: %v->%v", p.conn.LocalAddr(), p.conn.RemoteAddr())
			return nil, err
		}
		if err != nil {
			log.Printf("readMsg err: %v->%v: %v", p.conn.LocalAddr(), p.conn.RemoteAddr(), err)
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
			log.Printf("recevied msg id in downloadBlk %v", msg.MsgID)
		}
		// p.conn.SetDeadline(time.Time{})
	}
}

func (p *Peer) connect(hash []byte) error {
	supportExtension, err := p.handshake(hash)
	log.Printf("connecting %v->%v, err: %v", p.conn.LocalAddr(), p.conn.RemoteAddr(), err)
	if err != nil {
		p.Close()
		return err
	}

	if supportExtension {
		h := [20]byte(hash)
		if err := p.exchangeMetadata(h, p.magnetMeta.Tracker); err != nil {
			return err
		}
	}

	_, err = p.waitUntilPeerMessage(bitfield, "bitfield")
	if err != nil {
		return err
	}

	return nil
}

func (p *Peer) handshakeExt(hash []byte) error {
	supportExtension, err := p.handshake(hash[:])
	if err != nil {
		return err
	}
	if !supportExtension {
		return nil
	}
	_, err = p.waitUntilPeerMessage(bitfield, "bitfield")
	if err != nil {
		return err
	}

	ut := map[string]any{"m": map[string]any{"ut_metadata": utMetadata}}
	pkt := extensionPkt(extensionHandshake, ut)

	_, err = p.conn.Write(pkt)
	if err != nil {
		return err
	}

	msg, err := p.waitUntilPeerMessage(extension, "extenstion handshake resp")
	if err != nil {
		return err
	}
	log.Printf("extension handshake resp: %+v, payload: %v", msg, msg.Payload)

	peerExtenstion := msg.Payload[1:]
	mm, err := decodeBencode(string(peerExtenstion))
	if err != nil {
		return err
	}

	p.extensions = mm.(map[string]any)["m"].(map[string]any)
	log.Printf("peer extensions: %+v", p.extensions)

	return nil
}

func (p *Peer) handshake(hash []byte) (bool, error) {
	p.conn = nil
	p.unchoked = false
	for p.conn == nil {
		conn, err := net.Dial("tcp", p.addr)
		if err != nil {
			log.Printf("dial tcp error: %v", err)
			continue
		}
		// conn.SetDeadline(time.Time{})
		p.conn = conn
		break
	}

	pkt := handshakePkt(hash[:], p.supportExtension)
	_, err := p.conn.Write(pkt)
	if err != nil {
		return false, fmt.Errorf("send to %v err: %v", p.addr, err)
	}

	resp := &HandShakeMessage{}
	if err := binary.Read(p.conn, binary.BigEndian, &resp.Length); err != nil {
		return false, err
	}

	magic := make([]byte, resp.Length)
	if err := binary.Read(p.conn, binary.BigEndian, magic); err != nil {
		return false, err
	}

	// resp.MagicHeader = string(magic)
	if err := binary.Read(p.conn, binary.BigEndian, resp.Reserved[:]); err != nil {
		return false, err
	}
	if err := binary.Read(p.conn, binary.BigEndian, resp.InfoHash[:]); err != nil {
		return false, err
	}
	if err := binary.Read(p.conn, binary.BigEndian, resp.PeerID[:]); err != nil {
		return false, err
	}

	copy(p.id[:], resp.PeerID[:])
	log.Printf("handshake: %v, %v", p.id, p.addr)

	// TODO: abstract the "Reserved" field
	if resp.Reserved[5] != 0x10 {
		return false, nil
	}

	log.Printf("%x supports extenstion", p.id)
	return true, nil

}

func (p *Peer) magnetDownloadPiece(pIdx int) ([]byte, error) {
	pp := PeerPool{
		available: make(chan *Peer, 100),
		pending:   make(chan *Peer, 100),
		close:     make(chan int),
		hash:      p.magnetMeta.Hash[:],
	}

	err := pp.reuse(p)
	if err != nil {
		return nil, err
	}

	pd := PieceDownloader{
		pp:  &pp,
		t:   p.magnetMeta.Torrent,
		idx: pIdx,
	}
	go pp.run()

	if err := pd.run(); err != nil {
		return nil, err
	}

	log.Printf("closing peerpool")
	close(pp.close)
	pp.clean()

	return pd.piece, nil
}

func (p *Peer) exchangeMetadata(hash [20]byte, url string) error {
	// TODO: Since we're only requesting one piece in this challenge, this will always be 0
	// a piece is 16KiB, the metadata can consist of multiple pieces.
	mt := map[string]any{"msg_type": metaRequest, "piece": 0}
	pkt := extensionPkt(byte(p.extensions["ut_metadata"].(int)), mt)
	_, err := p.conn.Write(pkt)
	if err != nil {
		return err
	}

	msg, err := p.waitUntilPeerMessage(extension, "extension metadata resp")
	if err != nil {
		return err
	}
	log.Printf("metadata resp: %+v, payload: %v", msg, msg.Payload)
	m, err := decodeBencode(string(msg.Payload[1:]))
	if err != nil {
		return err
	}
	mt = m.(map[string]any)
	sz := mt["total_size"].(int)
	if x := mt["msg_type"].(int); x != metaData {
		return fmt.Errorf("should receive msg_type=1, but got %v", x)
	}

	md, err := decodeBencode(string(msg.Payload[len(msg.Payload)-sz : len(msg.Payload)]))
	if err != nil {
		return err
	}
	mdd := md.(map[string]any)

	hashes := []byte(mdd["pieces"].(string))

	if len(hashes)%20 != 0 {
		return fmt.Errorf("bad hashes : %v/%d", hashes, len(hashes))
	}

	hs := make([]string, 0, len(hashes)/20)
	for i := 0; i < len(hashes); i += 20 {
		hs = append(hs, hex.EncodeToString(hashes[i:i+20]))
	}
	meta := Torrent{
		Length:      mdd["length"].(int),
		PieceLength: mdd["piece length"].(int),
		PieceHashes: hs,
		Tracker:     url,
		Hash:        hash,
	}
	p.magnetMeta = &MagnetMeta{
		Name:    mdd["name"].(string),
		Torrent: meta,
	}

	log.Printf("peer file metadata: %+v", p.magnetMeta)
	return nil
}

func (p *Peer) waitUntilPeerMessage(id uint8, name string) (*PeerMessage, error) {
	var msg *PeerMessage
	var err error
	for {
		msg, err = p.readMsg(name)
		if err == io.EOF {
			return nil, err
		}
		if err != nil {
			continue
		}
		if msg.MsgID == id {
			// For bitfield, you can read and ignore the payload for now, the tracker we use for this challenge ensures that all peers have all pieces available.
			break
		} else {
			log.Printf("recevied %v when expecting %d/%s", msg.MsgID, id, name)
		}
	}

	return msg, err
}

type PeerPool struct {
	// to avoid `panic: send on closed channel` during cleanup
	//   1. atomic / mutex
	//  *2. once: pending closed itself*
	pending   chan *Peer
	available chan *Peer

	hash  []byte
	close chan int
}

func (pp *PeerPool) reconnect(p *Peer) error {
	select {
	case <-pp.close:
		return fmt.Errorf("reconnect err: peer pool closed")
	default:
		pp.pending <- p
	}
	return nil
}

func (pp *PeerPool) reuse(p *Peer) error {
	select {
	case <-pp.close:
		return fmt.Errorf("reuse err: peer pool closed")
	default:
		pp.available <- p
	}
	return nil
}

func (pp *PeerPool) clean() error {
	log.Printf("cleaning pendings")
	for p := range pp.pending {
		p.Close()
	}
	log.Printf("cleaning availables")
	for p := range pp.available {
		p.Close()
	}
	return nil
}

func (pp *PeerPool) run() error {
	go func() {
		for {
			log.Printf("try to  get a pending")
			select {
			case <-pp.close:
				log.Printf("close channels")
				close(pp.pending)
				close(pp.available)
				return
			case p := <-pp.pending:
				if err := p.connect(pp.hash); err != nil {
					p.Close()
					pp.reconnect(p)
				} else {
					pp.reuse(p)
				}
			}
		}
	}()
	<-pp.close
	log.Printf("peer pool stopped")
	return nil
}

type PieceDownloader struct {
	pp          *PeerPool
	piece       []byte
	t           Torrent
	idx         int // piece idx
	pieceLen    int
	blkCnt      int
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
	pieceCnt := int(math.Ceil(float64(pd.t.Length) / float64(pd.t.PieceLength)))
	if pieceCnt != len(pd.t.PieceHashes) {
		return fmt.Errorf("unmatched pieceCnt: %v/%v", pieceCnt, len(pd.t.PieceHashes))
	}
	pLen := pd.t.PieceLength
	if pd.idx == pieceCnt-1 {
		pLen = pd.t.Length - (pieceCnt-1)*pd.t.PieceLength
	}
	pd.blkCnt = int(math.Ceil(float64(pLen) / float64(blockSize)))
	pd.pieceLen = pLen
	pd.pendindTask = make(chan blockTask, pd.blkCnt)
	pd.done = make(chan int, pd.blkCnt)
	pd.piece = make([]byte, pLen)

	log.Printf("piece downloader: pIdx=%d, blkCnt=%d, pLen=%d, bsize=%d", pd.idx, pd.blkCnt, pd.pieceLen, blockSize)

	for i := range workingThreads {
		go func() {
			log.Printf("downloader %d started...", i)
			defer log.Printf("downloader %d stopped...", i)
			for b := range pd.pendindTask {
				log.Printf("blk %d, try to get available...", b.idx)
				p := <-pd.pp.available
				log.Printf("get an available: %x %s<->%s", p.id, p.conn.LocalAddr(), p.conn.RemoteAddr())
				if blk, err := p.downloadBlk(b); err != nil {
					p.Close()
					pd.pp.reconnect(p)
					pd.pendindTask <- b
				} else {
					l := b.idx * blockSize
					size := blockSize
					if b.idx == pd.blkCnt-1 {
						size = pLen - b.idx*blockSize
					}
					if size != len(blk) {
						log.Fatalf("??? size: %d, len(blk): %d", size, blk)
					}
					copy(pd.piece[l:l+size], blk)
					log.Printf("blk %v/%v finished, [%v:%v]", b.idx, pd.blkCnt, l, l+size)
					if err := pd.pp.reuse(p); err != nil {
						log.Printf("reuse: %v", err)
					}
					pd.done <- 1
				}
			}
		}()
	}

	go func() {
		for i := range pd.blkCnt {
			pd.pendindTask <- blockTask{
				idx:  i,
				cnt:  pd.blkCnt,
				pIdx: pd.idx,
				pLen: pLen,
			}
		}
	}()

	doneCnt := 0
	for d := range pd.done {
		doneCnt += d
		log.Printf("[p: %d] blk tasks finished: %d/%d", pd.idx, doneCnt, pd.blkCnt)
		if doneCnt == pd.blkCnt {
			break
		}
	}
	close(pd.pendindTask)
	log.Printf("piece downloader stopped: %v/%v", len(pd.piece), pd.pieceLen)

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

func (msg *PeerMessage) Unpack(name string, r io.Reader) error {
	if err := binary.Read(r, binary.BigEndian, &msg.Length); err != nil {
		log.Printf("[%v]read length err: %v", name, err)
		return err
	}
	if err := binary.Read(r, binary.BigEndian, &msg.MsgID); err != nil {
		log.Printf("[%v]read msgid err: %v", name, err)
		return err
	}
	body := make([]byte, msg.Length-1)
	if err := binary.Read(r, binary.BigEndian, &body); err != nil {
		log.Printf("[%v]read body err: %v", name, err)
		return err
	}
	msg.Payload = body
	return nil
}

const (
	utMetadata = 101

	metaRequest = 0
	metaData    = 1
	metaReject  = 2
)

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

	extension = 20
)

const (
	extensionHandshake = 0
)

func (c *Client) downloadPiece(pIdx int) ([]byte, error) {
	log.Printf("torrent info: %+v", c.t)
	pp := PeerPool{
		available: make(chan *Peer, 100),
		pending:   make(chan *Peer, 100),
		close:     make(chan int),
		hash:      c.t.Hash[:],
	}

	for j := range len(c.targets) {
		for range connPerTarget {
			p := &Peer{
				addr: c.targets[j].String(),
				conn: nil,
				id:   [20]byte{},
			}
			if err := pp.reconnect(p); err != nil {
				log.Printf("reconnect: %v", err)
			}
		}
	}

	pd := PieceDownloader{
		pp:  &pp,
		t:   c.t,
		idx: pIdx,
	}
	go pp.run()

	if err := pd.run(); err != nil {
		return nil, err
	}

	log.Printf("closing peerpool")
	close(pp.close)
	pp.clean()

	return pd.piece, nil
}

const blockSize = 16 * 1024

func (c *Client) Close() error {
	if c.mainConn != nil {
		return c.mainConn.Close()
	}
	return nil
}
