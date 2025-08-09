package main

import (
	"encoding/binary"
	"math"
)

func handshakePkt(hash []byte) []byte {
	pkt := make([]byte, 1+19+8+20+20)
	pkt[0] = 19
	copy(pkt[1:20], "BitTorrent protocol")
	clear(pkt[20:28]) // reserved

	copy(pkt[28:48], hash[:])
	copy(pkt[48:68], myID[:])
	return pkt
}

func interestedPkt() []byte {
	msg := &PeerMessage{}
	msg.MsgID = interested
	msg.Payload = nil
	return msg.Pack()
}

func requestPkt(pIdx, blkId, pieceLen int) []byte {
	blkCnt := int(math.Ceil(float64(pieceLen) / float64(blockSize)))
	msg := &PeerMessage{}
	msg.MsgID = request
	msg.Payload = binary.BigEndian.AppendUint32(msg.Payload, uint32(pIdx))
	msg.Payload = binary.BigEndian.AppendUint32(msg.Payload, uint32(blkId*blockSize))
	size := blockSize
	if blkId == blkCnt-1 {
		size = pieceLen - blkId*blockSize
	}
	msg.Payload = binary.BigEndian.AppendUint32(msg.Payload, uint32(size))
	return msg.Pack()
}
