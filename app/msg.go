package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"
)

func handshakePkt(hash []byte, extension bool) []byte {
	pkt := make([]byte, 1+19+8+20+20)
	pkt[0] = 19
	copy(pkt[1:20], "BitTorrent protocol")
	clear(pkt[20:28]) // reserved
	if extension {
		// set the 20th bit from the right to 1 (0-indexed)
		pkt[25] = 0x10
	}

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
	log.Printf("requestPkt: [%d, %d, %d, %d]", pIdx, blkId, blkId*blockSize, size)
	msg.Payload = binary.BigEndian.AppendUint32(msg.Payload, uint32(size))
	return msg.Pack()
}

func extensionPkt(exID byte, dict map[string]any) []byte {
	msg := &PeerMessage{}
	msg.MsgID = extension

	msg.Payload = append(msg.Payload, exID)
	d, err := encode(dict)
	if err != nil {
		panic(fmt.Sprintf("encode %+v err: %v", dict, err))
	}
	msg.Payload = append(msg.Payload, d...)
	return msg.Pack()
}
