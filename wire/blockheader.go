// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2026 Paul Lamb
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"io"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

const (
	// BlockHeaderLenV1 is the size of a classic 80-byte block header.
	BlockHeaderLenV1 = 16 + (chainhash.HashSize * 2)

	// BlockHeaderLenV2 is the size of a Bitcoin BLAKE2b "header v2" block
	// header: the classic 80 bytes followed by 84 bytes of new fields.
	BlockHeaderLenV2 = BlockHeaderLenV1 + 84

	// MaxBlockHeaderPayload is the maximum number of bytes a block header
	// can be. Since the BLAKE2b hard fork a header is 80 or 164 bytes, and
	// the two widths can appear in the same run of headers.
	MaxBlockHeaderPayload = BlockHeaderLenV2

	// HeaderV2VersionFlag is the top bit of the version field. A header
	// carrying it is a 164-byte v2 header whose block id is computed with
	// BLAKE2b. It is self-describing: no activation height is needed to
	// parse a header, only to know whether a chain is expected to carry
	// them.
	HeaderV2VersionFlag uint32 = 0x80000000

	// HeaderFlagUseTimeOffset is the bit in a v2 header's Flags field that
	// says the wire time is the block time minus TimeOffset.
	HeaderFlagUseTimeOffset uint8 = 4

	// HeaderFlagAsicProfileMask selects which of the four second-pass
	// BLAKE2b layouts the mining hardware saw.
	HeaderFlagAsicProfileMask uint8 = 3
)

// BlockHeader defines information about a block and is used in the bitcoin
// block (MsgBlock) and headers (MsgHeaders) messages.
//
// Two header formats exist on the Bitcoin BLAKE2b chain. A classic header is
// 80 bytes and its block id is SHA256d of those bytes. A "v2" header, marked
// by HeaderV2VersionFlag in its serialized version word, is 164 bytes and its
// block id is computed with BLAKE2b (see blake2b.go). The v2-only fields below
// are zero on a classic header, and HeaderV2 says which format the header is.
type BlockHeader struct {
	// Version of the block.  This is not the same as the protocol version.
	// The HeaderV2VersionFlag bit is never carried here; it lives in
	// HeaderV2 and is re-applied on serialization.
	Version int32

	// Hash of the previous block header in the block chain.
	PrevBlock chainhash.Hash

	// Merkle tree reference to hash of all transactions for the block.
	MerkleRoot chainhash.Hash

	// Time the block was created.  This is, unfortunately, encoded as a
	// uint32 on the wire and therefore is limited to 2106.
	//
	// On a v2 header with HeaderFlagUseTimeOffset set, the wire carries
	// Timestamp minus TimeOffset; this field always holds the real block
	// time, reconstructed on read.
	Timestamp time.Time

	// Difficulty target for the block.
	Bits uint32

	// Nonce used to generate the block.
	Nonce uint32

	// HeaderV2 is true when this is a 164-byte BLAKE2b-chain header.
	HeaderV2 bool

	// Nonce2 and Nonce3 extend the nonce space for the mining hardware.
	Nonce2 uint32
	Nonce3 uint32

	// Extranonce is the 16-byte Stratum v1 extranonce.
	Extranonce [16]byte

	// TimeOffset is subtracted from Timestamp on the wire when
	// HeaderFlagUseTimeOffset is set in Flags.
	TimeOffset uint32

	// TxCount is the number of transactions in the block, committed in
	// the header. It must match the block body.
	TxCount uint16

	// Flags: bits 0-1 select the ASIC layout of the second BLAKE2b pass,
	// bit 2 is HeaderFlagUseTimeOffset.
	Flags uint8

	// XorKeyMaskClearBits is how many leading bits of the XOR mask derived
	// from XorKey are cleared before it is applied to the block id.
	XorKeyMaskClearBits uint8

	// XorKey is the miner's block-withholding mitigation key.
	XorKey [16]byte

	// Height is the block height, committed in the header.
	Height int32

	// MMRhs is the merge-mining commitment (unused so far, all zero).
	MMRhs [32]byte
}

// blockHeaderLen is a constant that represents the number of bytes for a
// classic block header. Kept for callers that still assume a single width;
// prefer (*BlockHeader).SerializeSize.
const blockHeaderLen = BlockHeaderLenV1

// IsV2 reports whether this is a 164-byte BLAKE2b-chain header.
func (h *BlockHeader) IsV2() bool {
	return h.HeaderV2
}

// CompleteVersion returns the version word as it appears on the wire: the
// base version with HeaderV2VersionFlag set on a v2 header.
func (h *BlockHeader) CompleteVersion() uint32 {
	v := uint32(h.Version) &^ HeaderV2VersionFlag
	if h.HeaderV2 {
		v |= HeaderV2VersionFlag
	}
	return v
}

// TimeOnWire returns the timestamp as serialized: the block time, less
// TimeOffset (wrapping) when the header says the offset is in use.
func (h *BlockHeader) TimeOnWire() uint32 {
	t := uint32(h.Timestamp.Unix())
	if h.HeaderV2 && h.Flags&HeaderFlagUseTimeOffset != 0 {
		t -= h.TimeOffset
	}
	return t
}

// SerializeSize returns the number of bytes the header occupies when
// serialized: 80 for a classic header, 164 for a v2 header.
func (h *BlockHeader) SerializeSize() int {
	if h.HeaderV2 {
		return BlockHeaderLenV2
	}
	return BlockHeaderLenV1
}

// BlockHash computes the block identifier hash for the given block header.
// A classic header hashes with SHA256d; a v2 header with the BLAKE2b-chain
// construction.
func (h *BlockHeader) BlockHash() chainhash.Hash {
	if h.HeaderV2 {
		return h.blockHashV2()
	}
	return chainhash.DoubleHashRaw(func(w io.Writer) error {
		return writeBlockHeader(w, 0, h)
	})
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding block headers stored to disk, such as in a
// database, as opposed to decoding block headers from the wire.
func (h *BlockHeader) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	return readBlockHeader(r, pver, h)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding block headers to be stored to disk, such as in a
// database, as opposed to encoding block headers for the wire.
func (h *BlockHeader) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	return writeBlockHeader(w, pver, h)
}

// Deserialize decodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
func (h *BlockHeader) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of readBlockHeader.
	return readBlockHeader(r, 0, h)
}

// Serialize encodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
func (h *BlockHeader) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of writeBlockHeader.
	return writeBlockHeader(w, 0, h)
}

// NewBlockHeader returns a new BlockHeader using the provided version, previous
// block hash, merkle root hash, difficulty bits, and nonce used to generate the
// block with defaults for the remaining fields.
func NewBlockHeader(version int32, prevHash, merkleRootHash *chainhash.Hash,
	bits uint32, nonce uint32) *BlockHeader {

	// Limit the timestamp to one second precision since the protocol
	// doesn't support better.
	return &BlockHeader{
		Version:    version,
		PrevBlock:  *prevHash,
		MerkleRoot: *merkleRootHash,
		Timestamp:  time.Unix(time.Now().Unix(), 0),
		Bits:       bits,
		Nonce:      nonce,
	}
}

// readBlockHeader reads a bitcoin block header from r.  See Deserialize for
// decoding block headers stored to disk, such as in a database, as opposed to
// decoding from the wire.
//
// DEPRECATED: Use readBlockHeaderBuf instead.
func readBlockHeader(r io.Reader, pver uint32, bh *BlockHeader) error {
	buf := binarySerializer.Borrow()
	err := readBlockHeaderBuf(r, pver, bh, buf)
	binarySerializer.Return(buf)
	return err
}

// readBlockHeaderBuf reads a bitcoin block header from r.  See Deserialize for
// decoding block headers stored to disk, such as in a database, as opposed to
// decoding from the wire.
//
// The width is decided by the version word: a header with HeaderV2VersionFlag
// set is followed by 84 more bytes. A classic header leaves every v2 field
// zero, including on a reused receiver.
//
// If b is non-nil, the provided buffer will be used for serializing small
// values.  Otherwise a buffer will be drawn from the binarySerializer's pool
// and return when the method finishes.
//
// NOTE: b MUST either be nil or at least an 8-byte slice.
func readBlockHeaderBuf(r io.Reader, pver uint32, bh *BlockHeader,
	buf []byte) error {

	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return err
	}
	version := littleEndian.Uint32(buf[:4])
	bh.HeaderV2 = version&HeaderV2VersionFlag != 0
	bh.Version = int32(version &^ HeaderV2VersionFlag)

	if _, err := io.ReadFull(r, bh.PrevBlock[:]); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, bh.MerkleRoot[:]); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return err
	}
	timeOnWire := littleEndian.Uint32(buf[:4])

	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return err
	}
	bh.Bits = littleEndian.Uint32(buf[:4])

	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return err
	}
	bh.Nonce = littleEndian.Uint32(buf[:4])

	if !bh.HeaderV2 {
		bh.Nonce2 = 0
		bh.Nonce3 = 0
		bh.Extranonce = [16]byte{}
		bh.TimeOffset = 0
		bh.TxCount = 0
		bh.Flags = 0
		bh.XorKeyMaskClearBits = 0
		bh.XorKey = [16]byte{}
		bh.Height = 0
		bh.MMRhs = [32]byte{}
		bh.Timestamp = time.Unix(int64(timeOnWire), 0)
		return nil
	}

	if _, err := io.ReadFull(r, buf[:8]); err != nil {
		return err
	}
	bh.Nonce2 = littleEndian.Uint32(buf[:4])
	bh.Nonce3 = littleEndian.Uint32(buf[4:8])

	if _, err := io.ReadFull(r, bh.Extranonce[:]); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, buf[:8]); err != nil {
		return err
	}
	bh.TimeOffset = littleEndian.Uint32(buf[:4])
	bh.TxCount = littleEndian.Uint16(buf[4:6])
	bh.Flags = buf[6]
	bh.XorKeyMaskClearBits = buf[7]

	if _, err := io.ReadFull(r, bh.XorKey[:]); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return err
	}
	bh.Height = int32(littleEndian.Uint32(buf[:4]))

	if _, err := io.ReadFull(r, bh.MMRhs[:]); err != nil {
		return err
	}

	// The wire carries the time less the offset; reconstruct the block time
	// the way Knots does (wrapping add).
	blockTime := timeOnWire
	if bh.Flags&HeaderFlagUseTimeOffset != 0 {
		blockTime += bh.TimeOffset
	}
	bh.Timestamp = time.Unix(int64(blockTime), 0)

	return nil
}

// writeBlockHeader writes a bitcoin block header to w.  See Serialize for
// encoding block headers to be stored to disk, such as in a database, as
// opposed to encoding for the wire.
//
// DEPRECATED: Use writeBlockHeaderBuf instead.
func writeBlockHeader(w io.Writer, pver uint32, bh *BlockHeader) error {
	buf := binarySerializer.Borrow()
	err := writeBlockHeaderBuf(w, pver, bh, buf)
	binarySerializer.Return(buf)
	return err
}

// writeBlockHeaderBuf writes a bitcoin block header to w.  See Serialize for
// encoding block headers to be stored to disk, such as in a database, as
// opposed to encoding for the wire.
//
// If b is non-nil, the provided buffer will be used for serializing small
// values.  Otherwise a buffer will be drawn from the binarySerializer's pool
// and return when the method finishes.
//
// NOTE: b MUST either be nil or at least an 8-byte slice.
func writeBlockHeaderBuf(w io.Writer, pver uint32, bh *BlockHeader,
	buf []byte) error {

	littleEndian.PutUint32(buf[:4], bh.CompleteVersion())
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	if _, err := w.Write(bh.PrevBlock[:]); err != nil {
		return err
	}

	if _, err := w.Write(bh.MerkleRoot[:]); err != nil {
		return err
	}

	littleEndian.PutUint32(buf[:4], bh.TimeOnWire())
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	littleEndian.PutUint32(buf[:4], bh.Bits)
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	littleEndian.PutUint32(buf[:4], bh.Nonce)
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	if !bh.HeaderV2 {
		return nil
	}

	littleEndian.PutUint32(buf[:4], bh.Nonce2)
	littleEndian.PutUint32(buf[4:8], bh.Nonce3)
	if _, err := w.Write(buf[:8]); err != nil {
		return err
	}

	if _, err := w.Write(bh.Extranonce[:]); err != nil {
		return err
	}

	littleEndian.PutUint32(buf[:4], bh.TimeOffset)
	littleEndian.PutUint16(buf[4:6], bh.TxCount)
	buf[6] = bh.Flags
	buf[7] = bh.XorKeyMaskClearBits
	if _, err := w.Write(buf[:8]); err != nil {
		return err
	}

	if _, err := w.Write(bh.XorKey[:]); err != nil {
		return err
	}

	littleEndian.PutUint32(buf[:4], uint32(bh.Height))
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	if _, err := w.Write(bh.MMRhs[:]); err != nil {
		return err
	}

	return nil
}
