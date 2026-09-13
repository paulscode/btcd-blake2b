// Copyright (c) 2026 Paul Lamb
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// headerV2Vector is one entry of Bitcoin Knots' src/test/data/block_header_v2.json,
// the cross-implementation vectors for the BLAKE2b block id. Every stage of
// the computation is published so a failure names the stage.
type headerV2Vector struct {
	Name        string `json:"name"`
	AsicProfile int    `json:"asic_profile"`
	Serialized  string `json:"serialized"`
	XorKeyHash  string `json:"xor_key_hash"`
	H1          string `json:"h1"`
	H2          string `json:"h2"`
	Blake2b1    string `json:"blake2b_1"`
	AsicInput   string `json:"asic_input"`
	Blake2b2    string `json:"blake2b_2"`
	Mask        string `json:"mask"`
	BlockHash   string `json:"block_hash"`
}

func loadHeaderV2Vectors(t *testing.T) []headerV2Vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "block_header_v2.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file struct {
		Headers []headerV2Vector `json:"headers"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(file.Headers) != 5 {
		t.Fatalf("expected the 5 published vectors, got %d", len(file.Headers))
	}
	return file.Headers
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestBlockHeaderV2Vectors checks every intermediate of the v2 block id
// against the published Knots vectors, covering all four ASIC layouts and the
// XOR-mask clear-bit boundaries including the partial-byte case.
func TestBlockHeaderV2Vectors(t *testing.T) {
	profiles := map[int]bool{}
	for _, v := range loadHeaderV2Vectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			serialized := mustHex(t, v.Serialized)
			if len(serialized) != BlockHeaderLenV2 {
				t.Fatalf("vector is %d bytes, want %d", len(serialized),
					BlockHeaderLenV2)
			}

			var h BlockHeader
			if err := h.Deserialize(bytes.NewReader(serialized)); err != nil {
				t.Fatalf("deserialize: %v", err)
			}
			if !h.IsV2() {
				t.Fatal("v2 flag not detected")
			}
			if int(h.Flags&HeaderFlagAsicProfileMask) != v.AsicProfile {
				t.Fatalf("profile: got %d, want %d",
					h.Flags&HeaderFlagAsicProfileMask, v.AsicProfile)
			}
			profiles[v.AsicProfile] = true

			d := h.digestV2()
			check := func(stage string, got []byte, want string) {
				t.Helper()
				if hex.EncodeToString(got) != want {
					t.Errorf("%s: got %x, want %s", stage, got, want)
				}
			}
			check("xor_key_hash", d.xorKeyHash[:], v.XorKeyHash)
			check("h1", d.h1[:], v.H1)
			check("h2", d.h2[:], v.H2)
			check("blake2b_1", d.root[:], v.Blake2b1)
			check("asic_input", d.asicInput, v.AsicInput)
			check("blake2b_2", d.hash2[:], v.Blake2b2)
			check("mask", d.mask[:], v.Mask)
			if got := h.BlockHash().String(); got != v.BlockHash {
				t.Errorf("block_hash: got %s, want %s", got, v.BlockHash)
			}

			// The header must round-trip byte for byte.
			var buf bytes.Buffer
			if err := h.Serialize(&buf); err != nil {
				t.Fatalf("serialize: %v", err)
			}
			if !bytes.Equal(buf.Bytes(), serialized) {
				t.Errorf("round trip differs:\n got %x\nwant %x",
					buf.Bytes(), serialized)
			}
			if h.SerializeSize() != BlockHeaderLenV2 {
				t.Errorf("SerializeSize: got %d, want %d", h.SerializeSize(),
					BlockHeaderLenV2)
			}
		})
	}
	for p := 0; p < 4; p++ {
		if !profiles[p] {
			t.Errorf("vectors do not cover ASIC profile %d", p)
		}
	}
}

// mainnetHeader is one entry of testdata/blake2b_mainnet_headers.json: a
// header read from a Bitcoin Knots v29.4.1 node on the BLAKE2b mainnet on
// 2026-09-12, with the block hash the node reports for it.
type mainnetHeader struct {
	Height     int32   `json:"height"`
	Hash       string  `json:"hash"`
	Raw        string  `json:"raw"`
	Width      int     `json:"width"`
	NTx        int     `json:"ntx"`
	XorKey     string  `json:"xor_key"`
	XorClear   *uint8  `json:"xor_clear"`
	Flags      *uint8  `json:"flags"`
	TimeOffset *uint32 `json:"time_offset"`
	Time       int64   `json:"time"`
	Version    int32   `json:"version"`
}

func loadMainnetHeaders(t *testing.T) []mainnetHeader {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "blake2b_mainnet_headers.json"))
	if err != nil {
		t.Fatalf("read mainnet headers: %v", err)
	}
	var hs []mainnetHeader
	if err := json.Unmarshal(raw, &hs); err != nil {
		t.Fatalf("parse mainnet headers: %v", err)
	}
	if len(hs) < 200 {
		t.Fatalf("expected a few hundred headers, got %d", len(hs))
	}
	return hs
}

// TestBlockHeaderMainnetAcrossActivation replays real headers on both sides of
// the BLAKE2b activation at height 961640 and checks that the block id this
// package computes is the one the node reports, that the width flips exactly
// at activation, and that every parsed field matches the node's verbose view.
func TestBlockHeaderMainnetAcrossActivation(t *testing.T) {
	const activationHeight = 961640
	const activationHash = "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb"

	sawActivation := false
	sawV1, sawV2 := 0, 0
	for _, mh := range loadMainnetHeaders(t) {
		raw := mustHex(t, mh.Raw)
		var h BlockHeader
		if err := h.Deserialize(bytes.NewReader(raw)); err != nil {
			t.Fatalf("height %d: deserialize: %v", mh.Height, err)
		}

		wantV2 := mh.Height >= activationHeight
		if h.IsV2() != wantV2 {
			t.Errorf("height %d: IsV2=%v, want %v", mh.Height, h.IsV2(), wantV2)
		}
		if h.SerializeSize() != len(raw) {
			t.Errorf("height %d: SerializeSize=%d, raw is %d bytes",
				mh.Height, h.SerializeSize(), len(raw))
		}
		if got := h.BlockHash().String(); got != mh.Hash {
			t.Errorf("height %d: block hash %s, node says %s",
				mh.Height, got, mh.Hash)
		}
		if h.Version != mh.Version {
			t.Errorf("height %d: version %d, node says %d (the v2 bit "+
				"must not leak into Version)", mh.Height, h.Version, mh.Version)
		}
		if h.Timestamp.Unix() != mh.Time {
			t.Errorf("height %d: time %d, node says %d", mh.Height,
				h.Timestamp.Unix(), mh.Time)
		}
		if wantV2 {
			sawV2++
			if h.Height != mh.Height {
				t.Errorf("height %d: header commits to height %d",
					mh.Height, h.Height)
			}
			if int(h.TxCount) != mh.NTx {
				t.Errorf("height %d: header txcount %d, node nTx %d",
					mh.Height, h.TxCount, mh.NTx)
			}
			if hex.EncodeToString(h.XorKey[:]) != mh.XorKey {
				t.Errorf("height %d: xor key %x, node says %s",
					mh.Height, h.XorKey, mh.XorKey)
			}
			if mh.Flags != nil && h.Flags != *mh.Flags {
				t.Errorf("height %d: flags %d, node says %d",
					mh.Height, h.Flags, *mh.Flags)
			}
			if mh.XorClear != nil && h.XorKeyMaskClearBits != *mh.XorClear {
				t.Errorf("height %d: clear bits %d, node says %d",
					mh.Height, h.XorKeyMaskClearBits, *mh.XorClear)
			}
			if mh.TimeOffset != nil && h.TimeOffset != *mh.TimeOffset {
				t.Errorf("height %d: time offset %d, node says %d",
					mh.Height, h.TimeOffset, *mh.TimeOffset)
			}
		} else {
			sawV1++
		}
		if mh.Height == activationHeight {
			sawActivation = true
			if mh.Hash != activationHash {
				t.Errorf("activation block hash in fixture is %s, want %s",
					mh.Hash, activationHash)
			}
		}

		var buf bytes.Buffer
		if err := h.Serialize(&buf); err != nil {
			t.Fatalf("height %d: serialize: %v", mh.Height, err)
		}
		if !bytes.Equal(buf.Bytes(), raw) {
			t.Errorf("height %d: round trip differs", mh.Height)
		}
	}
	if !sawActivation {
		t.Error("fixture does not contain the activation block")
	}
	if sawV1 == 0 || sawV2 == 0 {
		t.Errorf("fixture must straddle activation: %d v1, %d v2", sawV1, sawV2)
	}
}

// TestBlockHeaderV2TimeOffset checks that a header using the time-offset flag
// serializes the block time less the offset and reconstructs it on read,
// including the wrapping case, exactly as Knots' WrappingSubtract/WrappingAdd.
func TestBlockHeaderV2TimeOffset(t *testing.T) {
	base := BlockHeader{
		Version:    0x20000000,
		PrevBlock:  mainNetGenesisHash,
		MerkleRoot: mainNetGenesisMerkleRoot,
		Bits:       0x1a008d4f,
		Nonce:      1,
		HeaderV2:   true,
		TxCount:    1,
		Height:     961640,
	}

	tests := []struct {
		name       string
		blockTime  uint32
		offset     uint32
		flags      uint8
		wantOnWire uint32
	}{
		{"no flag, offset ignored", 1788070477, 600, 0, 1788070477},
		{"flag, plain subtract", 1788070477, 600, HeaderFlagUseTimeOffset, 1788070477 - 600},
		{"flag, wraps below zero", 10, 600, HeaderFlagUseTimeOffset, 0xFFFFFFFF - 589},
		{"flag with profile bits", 1788070477, 7, HeaderFlagUseTimeOffset | 2, 1788070477 - 7},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := base
			h.Timestamp = time.Unix(int64(tc.blockTime), 0)
			h.TimeOffset = tc.offset
			h.Flags = tc.flags

			if got := h.TimeOnWire(); got != tc.wantOnWire {
				t.Fatalf("TimeOnWire: got %d, want %d", got, tc.wantOnWire)
			}

			var buf bytes.Buffer
			if err := h.Serialize(&buf); err != nil {
				t.Fatal(err)
			}
			raw := buf.Bytes()
			if len(raw) != BlockHeaderLenV2 {
				t.Fatalf("serialized %d bytes", len(raw))
			}
			if got := littleEndian.Uint32(raw[68:72]); got != tc.wantOnWire {
				t.Fatalf("wire time field: got %d, want %d", got, tc.wantOnWire)
			}

			var back BlockHeader
			if err := back.Deserialize(bytes.NewReader(raw)); err != nil {
				t.Fatal(err)
			}
			if back.Timestamp.Unix() != int64(tc.blockTime) {
				t.Fatalf("reconstructed time %d, want %d",
					back.Timestamp.Unix(), tc.blockTime)
			}
			if !reflect.DeepEqual(back, h) {
				t.Fatalf("round trip differs:\n got %+v\nwant %+v", back, h)
			}
		})
	}
}

// TestBlockHeaderV1Unchanged pins the classic path: an 80-byte header still
// hashes with SHA256d, reports width 80, and never carries the v2 bit.
func TestBlockHeaderV1Unchanged(t *testing.T) {
	h := BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},
		MerkleRoot: mainNetGenesisMerkleRoot,
		Timestamp:  time.Unix(0x495fab29, 0),
		Bits:       0x1d00ffff,
		Nonce:      0x7c2bac1d,
	}
	if h.IsV2() || h.SerializeSize() != BlockHeaderLenV1 {
		t.Fatalf("classic header misreported: v2=%v size=%d", h.IsV2(),
			h.SerializeSize())
	}
	if got := h.BlockHash(); got != mainNetGenesisHash {
		t.Fatalf("genesis hash: got %s, want %s", got, mainNetGenesisHash)
	}
	if h.CompleteVersion() != 1 {
		t.Fatalf("CompleteVersion: got %#x, want 1", h.CompleteVersion())
	}

	// Setting the flag bit in Version directly must not turn a classic
	// header into a v2 header on the wire; HeaderV2 is the only switch.
	flag := HeaderV2VersionFlag // runtime value: the constant would overflow int32
	h.Version = int32(flag | 1)
	if h.CompleteVersion() != 1 {
		t.Fatalf("CompleteVersion must strip the flag bit from Version: %#x",
			h.CompleteVersion())
	}
}

// TestBlockHeaderReuseClearsV2Fields makes sure decoding a classic header
// into a receiver that previously held a v2 header zeroes every v2 field.
// A stale field would change the hash of a header that no longer owns it.
func TestBlockHeaderReuseClearsV2Fields(t *testing.T) {
	vectors := loadHeaderV2Vectors(t)
	var h BlockHeader
	if err := h.Deserialize(bytes.NewReader(mustHex(t, vectors[1].Serialized))); err != nil {
		t.Fatal(err)
	}
	if !h.IsV2() || h.XorKey == [16]byte{} {
		t.Fatal("expected a v2 header with a non-null xor key from vector 1")
	}

	var classic bytes.Buffer
	genesis := BlockHeader{
		Version:    1,
		MerkleRoot: mainNetGenesisMerkleRoot,
		Timestamp:  time.Unix(0x495fab29, 0),
		Bits:       0x1d00ffff,
		Nonce:      0x7c2bac1d,
	}
	if err := genesis.Serialize(&classic); err != nil {
		t.Fatal(err)
	}
	if err := h.Deserialize(bytes.NewReader(classic.Bytes())); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(h, genesis) {
		t.Fatalf("stale v2 fields survived a classic decode:\n got %+v\nwant %+v",
			h, genesis)
	}
}

// TestBlockHeaderV2Truncated checks that a v2 header cut short anywhere in
// its 84 extra bytes is an error, never a silently classic header.
func TestBlockHeaderV2Truncated(t *testing.T) {
	full := mustHex(t, loadHeaderV2Vectors(t)[0].Serialized)
	for n := BlockHeaderLenV1; n < BlockHeaderLenV2; n++ {
		var h BlockHeader
		if err := h.Deserialize(bytes.NewReader(full[:n])); err == nil {
			t.Fatalf("truncated to %d bytes decoded without error", n)
		}
	}
}

// TestMsgBlockV2TxCount checks that a block whose body disagrees with the
// transaction count its v2 header commits to is refused, and that a matching
// one decodes with the right header width.
func TestMsgBlockV2TxCount(t *testing.T) {
	hdr := mustHex(t, loadHeaderV2Vectors(t)[0].Serialized)
	var h BlockHeader
	if err := h.Deserialize(bytes.NewReader(hdr)); err != nil {
		t.Fatal(err)
	}

	// Build a body carrying exactly the committed number of coinbase-like
	// transactions.
	mk := func(count uint16) []byte {
		h2 := h
		h2.TxCount = count
		var buf bytes.Buffer
		if err := h2.Serialize(&buf); err != nil {
			t.Fatal(err)
		}
		if err := WriteVarInt(&buf, 0, uint64(h.TxCount)); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < int(h.TxCount); i++ {
			tx := NewMsgTx(1)
			tx.AddTxIn(&TxIn{PreviousOutPoint: OutPoint{Index: 0xffffffff},
				SignatureScript: []byte{0x51}})
			tx.AddTxOut(&TxOut{Value: 1, PkScript: []byte{0x51}})
			if err := tx.Serialize(&buf); err != nil {
				t.Fatal(err)
			}
		}
		return buf.Bytes()
	}

	var good MsgBlock
	if err := good.Deserialize(bytes.NewReader(mk(h.TxCount))); err != nil {
		t.Fatalf("matching block refused: %v", err)
	}
	if good.Header.SerializeSize() != BlockHeaderLenV2 ||
		len(good.Transactions) != int(h.TxCount) {
		t.Fatalf("decoded block wrong: width %d, %d txs",
			good.Header.SerializeSize(), len(good.Transactions))
	}
	if good.SerializeSize() != len(mk(h.TxCount)) {
		t.Fatalf("SerializeSize %d, raw is %d bytes", good.SerializeSize(),
			len(mk(h.TxCount)))
	}
	if good.BlockHash() != h.BlockHash() {
		t.Fatal("block hash must come from the v2 header")
	}

	var bad MsgBlock
	if err := bad.Deserialize(bytes.NewReader(mk(h.TxCount + 1))); err == nil {
		t.Fatal("body/header transaction count mismatch was accepted")
	}
	if _, err := bad.DeserializeTxLoc(bytes.NewBuffer(mk(h.TxCount + 1))); err == nil {
		t.Fatal("DeserializeTxLoc accepted a count mismatch")
	}
}

// TestMsgHeadersV2 checks a headers message carrying both widths.
func TestMsgHeadersV2(t *testing.T) {
	v2 := mustHex(t, loadHeaderV2Vectors(t)[0].Serialized)
	var h2 BlockHeader
	if err := h2.Deserialize(bytes.NewReader(v2)); err != nil {
		t.Fatal(err)
	}
	h1 := BlockHeader{
		Version:    1,
		MerkleRoot: mainNetGenesisMerkleRoot,
		Timestamp:  time.Unix(0x495fab29, 0),
		Bits:       0x1d00ffff,
		Nonce:      0x7c2bac1d,
	}

	msg := NewMsgHeaders()
	if err := msg.AddBlockHeader(&h1); err != nil {
		t.Fatal(err)
	}
	if err := msg.AddBlockHeader(&h2); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := msg.BtcEncode(&buf, ProtocolVersion, BaseEncoding); err != nil {
		t.Fatal(err)
	}
	// count(1) + (80 + 1) + (164 + 1)
	if want := 1 + BlockHeaderLenV1 + 1 + BlockHeaderLenV2 + 1; buf.Len() != want {
		t.Fatalf("encoded %d bytes, want %d", buf.Len(), want)
	}

	var back MsgHeaders
	if err := back.BtcDecode(bytes.NewReader(buf.Bytes()), ProtocolVersion, BaseEncoding); err != nil {
		t.Fatal(err)
	}
	if len(back.Headers) != 2 || back.Headers[0].IsV2() || !back.Headers[1].IsV2() {
		t.Fatalf("decoded headers wrong: %+v", back.Headers)
	}
	if back.Headers[1].BlockHash() != h2.BlockHash() {
		t.Fatal("v2 header hash changed through a headers message")
	}
}

// FuzzBlockHeaderRoundTrip decodes arbitrary bytes as a header and, when that
// succeeds, requires re-encoding and re-decoding to be a fixed point and the
// block id to be stable. Seeds are the published vectors and a classic header.
func FuzzBlockHeaderRoundTrip(f *testing.F) {
	raw, err := os.ReadFile(filepath.Join("testdata", "block_header_v2.json"))
	if err != nil {
		f.Fatal(err)
	}
	var file struct {
		Headers []headerV2Vector `json:"headers"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		f.Fatal(err)
	}
	for _, v := range file.Headers {
		b, _ := hex.DecodeString(v.Serialized)
		f.Add(b)
		f.Add(b[:BlockHeaderLenV1])
	}
	f.Add(make([]byte, BlockHeaderLenV1))
	f.Add(make([]byte, BlockHeaderLenV2))

	f.Fuzz(func(t *testing.T, data []byte) {
		var h BlockHeader
		if err := h.Deserialize(bytes.NewReader(data)); err != nil {
			return
		}
		var buf bytes.Buffer
		if err := h.Serialize(&buf); err != nil {
			t.Fatalf("serialize after successful decode: %v", err)
		}
		if buf.Len() != h.SerializeSize() {
			t.Fatalf("SerializeSize %d but wrote %d", h.SerializeSize(), buf.Len())
		}
		if !bytes.Equal(buf.Bytes(), data[:buf.Len()]) {
			t.Fatalf("not a fixed point:\n in  %x\n out %x", data[:buf.Len()], buf.Bytes())
		}
		var back BlockHeader
		if err := back.Deserialize(bytes.NewReader(buf.Bytes())); err != nil {
			t.Fatalf("re-decode: %v", err)
		}
		if !reflect.DeepEqual(back, h) {
			t.Fatalf("re-decode differs")
		}
		if back.BlockHash() != h.BlockHash() {
			t.Fatal("block hash not stable across round trip")
		}
	})
}

// FuzzMsgBlockDeserialize makes sure no input can panic the block decoder and
// that a decoded block re-serializes to its own SerializeSize.
func FuzzMsgBlockDeserialize(f *testing.F) {
	f.Add(blockOneBytes)
	f.Add(make([]byte, BlockHeaderLenV2+1))
	f.Fuzz(func(t *testing.T, data []byte) {
		var b MsgBlock
		if err := b.Deserialize(bytes.NewReader(data)); err != nil {
			return
		}
		var buf bytes.Buffer
		if err := b.Serialize(&buf); err != nil {
			t.Fatalf("serialize: %v", err)
		}
		if buf.Len() != b.SerializeSize() {
			t.Fatalf("SerializeSize %d but wrote %d", b.SerializeSize(), buf.Len())
		}
	})
}
