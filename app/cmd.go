package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

func handShake(target string, t Torrent) error {
	c := &Client{
		t: t,
	}
	defer c.Close()
	return c.handShake(target)
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
	c := &Client{
		t:       t,
		targets: targets,
	}
	defer c.Close()

	fd, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer fd.Close()
	for pIdx := range len(t.PieceHashes) {
		log.Printf("[xxxxx]: downloading %d/%d piece", pIdx+1, len(t.PieceHashes))
		if p, err := c.downloadPiece(pIdx); err != nil {
			return err
		} else {
			_, err := fd.Write(p)
			if err != nil {
				return err
			}
		}

	}
	return err
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
	if err := peer.handshake(t.Hash[:]); err != nil {
		return err
	}
	fmt.Printf("Peer ID: %x\n", peer.id)
	return nil
}
