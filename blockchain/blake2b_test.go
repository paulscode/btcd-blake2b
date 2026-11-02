// Copyright (c) 2026 Paul Lamb
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// The first BLAKE2b mainnet block (961640), as serialized by Bitcoin Knots
// v29.4.1 on 2026-09-12.
const activationHeaderRaw = "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc7684dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d0300000000000000000000001e0300000000000000000000000000000000000068ac0e000000000000000000000000000000000000000000000000000000000000000000"

func mustHeader(t *testing.T, rawHex string) *wire.BlockHeader {
	t.Helper()
	b, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatal(err)
	}
	var h wire.BlockHeader
	if err := h.Deserialize(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	return &h
}

func ruleCode(err error) (ErrorCode, bool) {
	var rerr RuleError
	if !errors.As(err, &rerr) {
		return 0, false
	}
	return rerr.ErrorCode, true
}

// knotsHeaders are real mainnet headers from a Bitcoin Knots v29.4.2 node,
// by height: wire's 278 headers around the activation, and the blocks around
// every difficulty retarget since (testdata/blake2b_retargets.json).
func knotsHeaders(t *testing.T) map[int32]*wire.BlockHeader {
	t.Helper()
	type entry struct {
		Height int32  `json:"height"`
		Hash   string `json:"hash"`
		Raw    string `json:"raw"`
	}
	hs := make(map[int32]*wire.BlockHeader)
	add := func(es []entry) {
		for _, e := range es {
			h := mustHeader(t, e.Raw)
			if got := h.BlockHash().String(); got != e.Hash {
				t.Fatalf("height %d: block id %s, node says %s",
					e.Height, got, e.Hash)
			}
			hs[e.Height] = h
		}
	}

	raw, err := os.ReadFile(filepath.Join("..", "wire", "testdata",
		"blake2b_mainnet_headers.json"))
	if err != nil {
		t.Fatal(err)
	}
	var around []entry
	if err := json.Unmarshal(raw, &around); err != nil {
		t.Fatal(err)
	}
	add(around)

	raw, err = os.ReadFile(filepath.Join("testdata", "blake2b_retargets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var retargets struct {
		Headers []entry `json:"headers"`
	}
	if err := json.Unmarshal(raw, &retargets); err != nil {
		t.Fatal(err)
	}
	add(retargets.Headers)
	return hs
}

// sparseHeaderCtx is a HeaderCtx over a sparse set of real headers: enough
// for difficulty checks, which only look at the parent and at the first block
// of the period.
type sparseHeaderCtx struct {
	hs     map[int32]*wire.BlockHeader
	height int32
}

func (s sparseHeaderCtx) Height() int32    { return s.height }
func (s sparseHeaderCtx) Bits() uint32     { return s.hs[s.height].Bits }
func (s sparseHeaderCtx) Timestamp() int64 { return s.hs[s.height].Timestamp.Unix() }
func (s sparseHeaderCtx) Parent() HeaderCtx {
	return s.RelativeAncestorCtx(1)
}
func (s sparseHeaderCtx) RelativeAncestorCtx(distance int32) HeaderCtx {
	if _, ok := s.hs[s.height-distance]; !ok {
		return nil
	}
	return sparseHeaderCtx{s.hs, s.height - distance}
}

// mainnetChainCtx is a ChainCtx with mainnet's retarget parameters.
type mainnetChainCtx struct{ params *chaincfg.Params }

func (m mainnetChainCtx) ChainParams() *chaincfg.Params { return m.params }
func (m mainnetChainCtx) BlocksPerRetarget() int32 {
	return int32(m.params.TargetTimespan / m.params.TargetTimePerBlock)
}
func (m mainnetChainCtx) MinRetargetTimespan() int64 {
	return int64(m.params.TargetTimespan/time.Second) / m.params.RetargetAdjustmentFactor
}
func (m mainnetChainCtx) MaxRetargetTimespan() int64 {
	return int64(m.params.TargetTimespan/time.Second) * m.params.RetargetAdjustmentFactor
}
func (m mainnetChainCtx) VerifyCheckpoint(int32, *chainhash.Hash) bool { return true }
func (m mainnetChainCtx) FindPreviousCheckpoint() (HeaderCtx, error)   { return nil, nil }

// TestBlake2bProofOfWorkMainnet checks every real v2 header against its
// target the way Knots' CheckBlockHeader does, and that a header whose id no
// longer meets the target, or with reserved flag bits, is refused.
func TestBlake2bProofOfWorkMainnet(t *testing.T) {
	powLimit := chaincfg.MainNetParams.PowLimit
	v2 := 0
	for height, h := range knotsHeaders(t) {
		if err := checkProofOfWork(h, powLimit, BFNone); err != nil {
			t.Fatalf("height %d (v2 %v): %v", height, h.IsV2(), err)
		}
		if !h.IsV2() {
			continue
		}
		v2++

		bad := *h
		bad.Nonce++
		if code, _ := ruleCode(checkProofOfWork(&bad, powLimit, BFNone)); code != ErrHighHash {
			t.Fatalf("height %d with another nonce: got %v, want ErrHighHash", height, code)
		}

		flagged := *h
		flagged.Flags |= 0x40
		if code, _ := ruleCode(checkProofOfWork(&flagged, powLimit, BFNoPoWCheck)); code != ErrBadHeaderV2 {
			t.Fatalf("height %d with a reserved flag: got %v, want ErrBadHeaderV2", height, code)
		}
	}
	if v2 < 250 {
		t.Fatalf("only %d v2 headers checked", v2)
	}

	// The classic path is unchanged: mainnet genesis passes.
	genesis := chaincfg.MainNetParams.GenesisBlock.Header
	if err := checkProofOfWork(&genesis, powLimit, BFNone); err != nil {
		t.Fatalf("genesis header refused: %v", err)
	}
}

// TestBlake2bDifficultyMainnet checks the target of the activation block (the
// usual one shifted by 22 bits) and of every retarget since against what the
// network actually used.
func TestBlake2bDifficultyMainnet(t *testing.T) {
	hs := knotsHeaders(t)
	c := mainnetChainCtx{&chaincfg.MainNetParams}
	next := func(height int32) uint32 {
		t.Helper()
		bits, err := calcNextRequiredDifficulty(sparseHeaderCtx{hs, height - 1},
			hs[height].Timestamp, c)
		if err != nil {
			t.Fatalf("height %d: %v", height, err)
		}
		return bits
	}

	// Activation: the shift, and nothing but the shift.
	if got, want := next(961640), hs[961640].Bits; got != want {
		t.Fatalf("activation target %08x, the chain has %08x", got, want)
	}
	if hs[961640].Bits == hs[961639].Bits {
		t.Fatal("fixture: the activation target should differ from its parent's")
	}
	if got := applyBlake2bTargetShift(hs[961639].Bits, c.params); got != hs[961640].Bits {
		t.Fatalf("shifted %08x to %08x, the chain has %08x", hs[961639].Bits, got, hs[961640].Bits)
	}
	// Either side of it the target carries over.
	for _, h := range []int32{961639, 961641} {
		if got, want := next(h), hs[h].Bits; got != want {
			t.Fatalf("height %d: target %08x, the chain has %08x", h, got, want)
		}
	}

	retargets := 0
	for h := int32(961632 + 2016); hs[h] != nil; h += 2016 {
		if got, want := next(h), hs[h].Bits; got != want {
			t.Fatalf("retarget at %d: target %08x, the chain has %08x", h, got, want)
		}
		retargets++
	}
	if retargets < 5 {
		t.Fatalf("only %d retargets checked", retargets)
	}
}

// TestBlake2bHeaderContext checks which proof of work each height requires
// (Knots' bad-version-sha256d, bad-version-blake2b, bad-header-height), and
// that a network without BLAKE2b configured still refuses v2 headers.
func TestBlake2bHeaderContext(t *testing.T) {
	params := &chaincfg.MainNetParams
	v2 := mustHeader(t, activationHeaderRaw)

	if err := checkHeaderV2Context(v2, 961640, params); err != nil {
		t.Fatalf("activation header at its height: %v", err)
	}
	if code, _ := ruleCode(checkHeaderV2Context(v2, 961639, params)); code != ErrBadHeaderV2 {
		t.Fatalf("v2 header below the activation: got %v, want ErrBadHeaderV2", code)
	}
	wrongHeight := *v2
	wrongHeight.Height++
	if code, _ := ruleCode(checkHeaderV2Context(&wrongHeight, 961640, params)); code != ErrBadHeaderV2 {
		t.Fatalf("v2 header committing to another height: got %v, want ErrBadHeaderV2", code)
	}

	classic := chaincfg.MainNetParams.GenesisBlock.Header
	if err := checkHeaderV2Context(&classic, 961639, params); err != nil {
		t.Fatalf("classic header below the activation: %v", err)
	}
	if code, _ := ruleCode(checkHeaderV2Context(&classic, 961640, params)); code != ErrBadHeaderV2 {
		t.Fatalf("classic header at the activation: got %v, want ErrBadHeaderV2", code)
	}

	// No BLAKE2b configured (a Params written before the rule): v2 is
	// refused, not checked.
	none := chaincfg.MainNetParams
	none.Blake2bHeight = 0
	if code, _ := ruleCode(checkHeaderV2Context(v2, 961640, &none)); code != ErrUnsupportedProofOfWork {
		t.Fatalf("v2 header without BLAKE2b configured: got %v, want ErrUnsupportedProofOfWork", code)
	}
	if err := checkHeaderV2Context(&classic, 961640, &none); err != nil {
		t.Fatalf("classic header without BLAKE2b configured: %v", err)
	}
}

// TestCheckHeaderV2Sanity pins the context-free rule Knots applies in
// CheckBlockHeader: a v2 header committing to the activation height is
// accepted, one committing to the block below it is refused (bad-version-
// sha256d), and a network without BLAKE2b configured takes no v2 header.
func TestCheckHeaderV2Sanity(t *testing.T) {
	params := &chaincfg.MainNetParams
	v2 := mustHeader(t, activationHeaderRaw)
	if v2.Height != 961640 {
		t.Fatalf("the activation header commits to %d", v2.Height)
	}

	if err := CheckHeaderV2Sanity(v2, params); err != nil {
		t.Fatalf("v2 header committing to the activation height: %v", err)
	}
	below := *v2
	below.Height = 961639
	if code, _ := ruleCode(CheckHeaderV2Sanity(&below, params)); code != ErrBadHeaderV2 {
		t.Fatalf("v2 header committing to the block below the activation: got %v, want ErrBadHeaderV2", code)
	}

	classic := chaincfg.MainNetParams.GenesisBlock.Header
	if err := CheckHeaderV2Sanity(&classic, params); err != nil {
		t.Fatalf("classic header: %v", err)
	}

	none := chaincfg.MainNetParams
	none.Blake2bHeight = 0
	if code, _ := ruleCode(CheckHeaderV2Sanity(v2, &none)); code != ErrUnsupportedProofOfWork {
		t.Fatalf("v2 header without BLAKE2b configured: got %v, want ErrUnsupportedProofOfWork", code)
	}
}

// TestProcessBlockHeaderV2Sanity checks that ProcessBlock applies
// CheckHeaderV2Sanity before a block is kept as an orphan, where the real
// height is not known yet: a v2 block committing to a height below the
// activation is refused, and the same block committing to the activation
// height is kept as an orphan.
func TestProcessBlockHeaderV2Sanity(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Blake2bHeight = 100
	chain, teardown, err := chainSetup("processv2sanity", &params)
	if err != nil {
		t.Fatalf("chain setup: %v", err)
	}
	defer teardown()

	orphanAt := func(height int32) *btcutil.Block {
		msg := *params.GenesisBlock
		msg.Header.HeaderV2 = true
		msg.Header.Height = height
		msg.Header.PrevBlock = chainhash.Hash{0x01}
		msg.Header.Timestamp = time.Unix(time.Now().Unix(), 0)
		return btcutil.NewBlock(&msg)
	}

	_, _, err = chain.ProcessBlock(orphanAt(99), BFNoPoWCheck)
	if code, _ := ruleCode(err); code != ErrBadHeaderV2 {
		t.Fatalf("v2 orphan committing to the block below the activation: "+
			"got %v, want ErrBadHeaderV2", err)
	}
	_, isOrphan, err := chain.ProcessBlock(orphanAt(100), BFNoPoWCheck)
	if err != nil || !isOrphan {
		t.Fatalf("v2 orphan committing to the activation height: orphan %v, %v",
			isOrphan, err)
	}
}
