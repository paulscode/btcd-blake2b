// Copyright (c) 2026 Paul Lamb
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"encoding/binary"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"golang.org/x/crypto/blake2b"
)

// The Bitcoin BLAKE2b chain (Bitcoin Knots v29.4.1, "header v2") replaced
// SHA256d proof of work at mainnet height 961640 and grew the block header
// from 80 to 164 bytes. The block id of a v2 header is not a hash of the
// serialized header. It is a tree of BIP-340 tagged SHA256 commitments over
// the header fields, hashed twice with BLAKE2b-256 in one of four layouts the
// mining hardware sees, then XORed with a mask derived from the miner's XOR
// key. This file mirrors CBlockHeader::GetHash() in Knots' primitives/block.cpp
// stage by stage so every intermediate can be checked against the published
// vectors in testdata/block_header_v2.json.
//
// Nothing here validates proof of work. A consumer of a bitcoind backend only
// needs to compute the same block id the node computes, because chain
// tracking compares the id of one block against the prev-hash of the next and
// reads a mismatch as a reorg.

var (
	tagXorKey     = []byte("Bitcoin block hash PoW XOR key")
	tagXorMask    = []byte("Bitcoin block hash PoW XOR mask")
	tagPrevHidden = []byte("Bitcoin prevblock header, hashed")
	tagHeader1    = []byte("Bitcoin block header 1")
	tagMergeMine  = []byte("Merge-mining hook")
)

// headerV2Digest holds every intermediate value of the v2 block id
// computation. Tests compare each against the vectors so a failure names the
// stage rather than the final hash.
type headerV2Digest struct {
	xorKeyHash [32]byte
	mask       [32]byte
	h1         [32]byte
	h2         [32]byte
	root       [32]byte // first BLAKE2b pass ("blake2b_1" in the vectors)
	asicInput  []byte
	hash2      [32]byte // second BLAKE2b pass ("blake2b_2")
	blockHash  chainhash.Hash
}

// blockHashV2 computes the BLAKE2b-chain block id of a v2 header.
func (h *BlockHeader) blockHashV2() chainhash.Hash {
	return h.digestV2().blockHash
}

// digestV2 runs the full v2 block id computation and returns every stage.
func (h *BlockHeader) digestV2() headerV2Digest {
	var d headerV2Digest

	// The pooled miner only learns the hash of the XOR key, so the key is
	// committed by hash and the mask is derived separately.
	d.xorKeyHash = *chainhash.TaggedHash(tagXorKey, h.XorKey[:])

	if h.XorKey != [16]byte{} {
		d.mask = *chainhash.TaggedHash(tagXorMask, h.XorKey[:])
		clearBytes := int(h.XorKeyMaskClearBits / 8)
		for i := 0; i < clearBytes && i < len(d.mask); i++ {
			d.mask[i] = 0
		}
		if clearBytes < len(d.mask) {
			d.mask[clearBytes] &= 0xff >> (h.XorKeyMaskClearBits % 8)
		}
	}

	// The previous block hash in "sane" (display) order, as Knots feeds it
	// to the commitments.
	var prevSane [32]byte
	for i := range prevSane {
		prevSane[i] = h.PrevBlock[len(h.PrevBlock)-1-i]
	}
	prevHidden := *chainhash.TaggedHash(tagPrevHidden, prevSane[:])

	// h1 commits to the fields the mining machine never sees, so a hasher
	// cannot brick itself on a future version, time or difficulty.
	var b [4]byte
	h1 := make([]byte, 0, 119)
	binary.LittleEndian.PutUint32(b[:], h.CompleteVersion())
	h1 = append(h1, b[:]...)
	h1 = append(h1, prevSane[:]...)
	binary.LittleEndian.PutUint32(b[:], uint32(h.Height))
	h1 = append(h1, b[:]...)
	h1 = append(h1, h.MerkleRoot[:]...)
	binary.LittleEndian.PutUint32(b[:], h.TimeOnWire())
	h1 = append(h1, b[:]...)
	h1 = append(h1, 0) // reserved for an extended 40-bit time
	binary.LittleEndian.PutUint32(b[:], h.Bits)
	h1 = append(h1, b[:]...)
	binary.LittleEndian.PutUint32(b[:], uint32(h.TxCount))
	h1 = append(h1, b[:]...)
	h1 = append(h1, h.Flags, h.XorKeyMaskClearBits)
	h1 = append(h1, d.xorKeyHash[:]...)
	d.h1 = *chainhash.TaggedHash(tagHeader1, h1)

	// h2 leaves room for a merge-mining commitment.
	var zeros32 [32]byte
	d.h2 = *chainhash.TaggedHash(tagMergeMine, d.h1[:], zeros32[:], h.MMRhs[:])

	// First BLAKE2b pass: what Stratum v1 carries as coinb1 + extranonce.
	ss := make([]byte, 0, 52)
	ss = append(ss, 0, 0, 0, 0)
	ss = append(ss, d.h2[:]...)
	ss = append(ss, h.Extranonce[:]...)
	d.root = blake2b.Sum256(ss)

	// Second BLAKE2b pass: the bytes the ASIC actually hashes, in one of four
	// layouts selected by the low two bits of the flags. Only layout 0 has
	// appeared on a live chain so far; the others are covered by vectors.
	var nonce, nonce2, nonce3, timeOffset [4]byte
	binary.LittleEndian.PutUint32(nonce[:], h.Nonce)
	binary.LittleEndian.PutUint32(nonce2[:], h.Nonce2)
	binary.LittleEndian.PutUint32(nonce3[:], h.Nonce3)
	binary.LittleEndian.PutUint32(timeOffset[:], h.TimeOffset)

	asic := make([]byte, 0, 144)
	switch h.Flags & 3 {
	case 3:
		asic = append(asic, zeros32[:]...)
		fallthrough
	case 2:
		asic = append(asic, zeros32[:]...)
		asic = append(asic, zeros32[:16]...)
		asic = append(asic, d.h2[:]...)
		asic = append(asic, nonce[:]...)
		asic = append(asic, nonce2[:]...)
		asic = append(asic, timeOffset[:]...)
		asic = append(asic, nonce3[:]...)
		asic = append(asic, d.root[:]...)
	case 0:
		hidden := prevHidden
		for i := 0; i < 6; i++ {
			hidden[i] = 0
		}
		asic = append(asic, hidden[:]...)
		asic = append(asic, nonce[:]...)
		asic = append(asic, nonce2[:]...)
		asic = append(asic, timeOffset[:]...)
		asic = append(asic, nonce3[:]...)
		asic = append(asic, d.root[:]...)
	case 1:
		asic = append(asic, nonce[:]...)
		asic = append(asic, nonce2[:]...)
		asic = append(asic, nonce3[:]...)
		asic = append(asic, timeOffset[:]...)
		asic = append(asic, d.root[:]...)
		asic = append(asic, d.h2[:]...)
	}
	d.asicInput = asic
	d.hash2 = blake2b.Sum256(asic)

	// Knots writes the masked digest into the uint256 back to front, so the
	// internal byte order of the block id is the reverse of (hash2 XOR mask).
	for i := range d.hash2 {
		d.blockHash[len(d.blockHash)-1-i] = d.hash2[i] ^ d.mask[i]
	}

	return d
}
