package main

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
	_, err := c.downloadPiece(pIdx, fname)
	return err
}
