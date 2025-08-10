package main

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
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
	const scheme = "magnet:?"
	l = strings.TrimSpace(l)
	if !strings.HasPrefix(l, scheme) {
		return fmt.Errorf("unrecognized scheme")
	}
	l = l[len(scheme):]
	v, err := url.ParseQuery(l)
	if err != nil {
		return err
	}

	xt, ok := v["xt"]
	if !ok {
		return fmt.Errorf("xt is required")
	}

	tr, _ := v["tr"]

	hash := xt[0]
	const magic = "urn:btih:"
	if !strings.HasPrefix(hash, magic) {
		return fmt.Errorf("bad hash: %v", hash)
	}
	hash = hash[len(magic):]
	url := tr[0]

	fmt.Printf("Tracker URL: %s\nInfo Hash: %s\n", url, hash)
	return nil
}
