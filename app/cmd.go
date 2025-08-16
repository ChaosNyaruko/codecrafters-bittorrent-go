package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

func handShake(target string, t Torrent) error {
	peer := Peer{
		addr:             target,
		conn:             nil,
		supportExtension: false,
		id:               [20]byte{},
	}
	defer peer.Close()
	if _, err := peer.handshake(t.Hash[:]); err != nil {
		return err
	}
	fmt.Printf("Peer ID: %x\n", peer.id)
	return nil
}

func downloadPiece(targets []Target, t Torrent, pIdx int, fname string) error {
	c := &Client{
		t:       t,
		targets: targets,
	}
	defer c.Close()
	pieceData, err := c.downloadPiece(pIdx)
	fd, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer fd.Close()
	_, err = fd.Write(pieceData)
	if err != nil {
		return err
	}

	return err
}

func downloadFile(targets []Target, t Torrent, fname string) error {

	fd, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer fd.Close()
	start := time.Now()
	defer func() {
		fmt.Printf("downloadFile %v[%dB] cost: %v", fname, t.Length, time.Since(start))
	}()

	sz := max(len(t.PieceHashes)/5, 1)
	const threadNum = 10
	res := make([]byte, t.Length)
	var wg sync.WaitGroup
	for i := range threadNum {
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			c := &Client{
				t:       t,
				targets: targets,
			}
			defer c.Close()
			log.Printf("[#%d piece downloader]: [%d,%d)/%d", i, start, end, len(t.PieceHashes))
			for pIdx := start; pIdx < end && pIdx < len(t.PieceHashes); pIdx++ {
				a := pIdx * t.PieceLength
				b := min((pIdx+1)*t.PieceLength, t.Length)
				// log.Printf("[#%d piece downloader]: downloading %d/%d piece, byte_offset: [%v, %v)",
				// 	l, pIdx+1, len(t.PieceHashes), a, b)
				var p []byte
				for p, err = c.downloadPiece(pIdx); err != nil; p, err = c.downloadPiece(pIdx) {
					log.Printf("[xxxxx]: downloading %d/%d piece err: %v", pIdx+1, len(t.PieceHashes), err)
				}
				copy(res[a:b], p[:])
			}
		}(i*sz, max((i+1)*sz, len(t.PieceHashes)-i*sz))

	}
	wg.Wait()
	_, err = fd.Write(res)
	if err != nil {
		return err
	}
	return nil
}

func parseMagnetlink(l string) error {
	if m, err := parseMagnet(l); err != nil {
		return err
	} else {
		fmt.Printf("Tracker URL: %s\nInfo Hash: %s\n", m.tracker, m.hash)
	}
	return nil
}

func magnetHandshake(l string) error {
	m, err := parseMagnet(l)
	if err != nil {
		return err
	}
	h, err := hex.DecodeString(m.hash)
	if err != nil || len(h) != 20 {
		return fmt.Errorf("decode hash[%v] err: %v", m.hash, err)
	}
	hash := [20]byte{}
	copy(hash[:], h)
	t := Torrent{
		Tracker:     m.tracker,
		Length:      0,
		Hash:        hash,
		PieceLength: 0,
		PieceHashes: []string{},
	}
	targets, err := getPeersFromTracker(t)
	if err != nil {
		return fmt.Errorf("get peers from tracker %q err: %v", t.Tracker, err)
	}

	// NOTE: the test suite ensures it has and only has one target.
	p := targets[0]
	peer := Peer{
		addr:             p.String(),
		conn:             nil,
		supportExtension: true,
		id:               [20]byte{},
	}
	defer peer.Close()
	if err := peer.handshakeExt(t.Hash[:]); err != nil {
		return err
	}

	fmt.Printf("Peer ID: %x\n", peer.id)
	fmt.Printf("Peer Metadata Extension ID: %d\n", peer.extensions["ut_metadata"].(int))
	return nil
}

func magnetInfo(l string) error {
	m, err := parseMagnet(l)
	if err != nil {
		return err
	}
	h, err := hex.DecodeString(m.hash)
	if err != nil || len(h) != 20 {
		return fmt.Errorf("decode hash[%v] err: %v", m.hash, err)
	}
	hash := [20]byte{}
	copy(hash[:], h)
	t := Torrent{
		Tracker:     m.tracker,
		Length:      0,
		Hash:        hash,
		PieceLength: 0,
		PieceHashes: []string{},
	}
	targets, err := getPeersFromTracker(t)
	if err != nil {
		return fmt.Errorf("get peers from tracker %q err: %v", t.Tracker, err)
	}

	// NOTE: the test suite ensures it has and only has one target.
	p := targets[0]
	peer := Peer{
		addr:             p.String(),
		conn:             nil,
		supportExtension: true,
		id:               [20]byte{},
	}
	defer peer.Close()
	err = peer.handshakeExt(t.Hash[:])

	if err := peer.exchangeMetadata(t.Hash, m.tracker); err != nil {
		return err
	}

	fmt.Printf("%s\n", peer.magnetMeta)

	return nil
}

func magnetDownload(l, fname string, pIdx int, fileMode bool) error {
	m, err := parseMagnet(l)
	if err != nil {
		return err
	}
	h, err := hex.DecodeString(m.hash)
	if err != nil || len(h) != 20 {
		return fmt.Errorf("decode hash[%v] err: %v", m.hash, err)
	}
	hash := [20]byte{}
	copy(hash[:], h)
	t := Torrent{
		Tracker:     m.tracker,
		Length:      0,
		Hash:        hash,
		PieceLength: 0,
		PieceHashes: []string{},
	}
	targets, err := getPeersFromTracker(t)
	if err != nil {
		return fmt.Errorf("get peers from tracker %q err: %v", t.Tracker, err)
	}

	// NOTE: the test suite ensures it has and only has one target.
	p := targets[0]
	peer := Peer{
		addr:             p.String(),
		conn:             nil,
		supportExtension: true,
		id:               [20]byte{},
	}
	defer peer.Close()
	if err := peer.handshakeExt(t.Hash[:]); err != nil {
		return err
	}

	if err := peer.exchangeMetadata(t.Hash, m.tracker); err != nil {
		return err
	}

	fd, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer fd.Close()
	if !fileMode {
		pieceData, err := peer.magnetDownloadPiece(pIdx)
		if err != nil {
			return err
		}
		_, err = fd.Write(pieceData)
		if err != nil {
			return err
		}
		return err
	}
	// TODO: concurrent downloading
	start := time.Now()
	defer func() {
		fmt.Printf("downloadFile %v[%dB] cost: %v", fname, peer.magnetMeta.Length, time.Since(start))
	}()
	for pIdx := range len(peer.magnetMeta.PieceHashes) {
		sp := Peer{
			addr:             peer.addr,
			conn:             peer.conn, // TODO: concurrency safety
			unchoked:         false,
			id:               peer.id,
			supportExtension: peer.supportExtension,
			extensions:       peer.extensions,
			magnetMeta:       peer.magnetMeta,
		}
		log.Printf("[%s]: downloading %d/%d piece", sp.magnetMeta.Name, pIdx+1, len(peer.magnetMeta.PieceHashes))
		if p, err := sp.magnetDownloadPiece(pIdx); err != nil {
			return err
		} else {
			_, err := fd.Write(p)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
