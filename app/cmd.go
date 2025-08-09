package main

import (
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
