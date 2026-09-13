// Copyright (c) 2026 The Lightning Fork developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// unifiedVector is one row of Knots' unified_sighash.json.
type unifiedVector struct {
	ScriptCode   string
	RawTx        string
	InIdx        int
	HashType     uint32
	ScriptType   int
	SpentOutputs [][2]interface{}
	SigHash      string
}

// loadUnifiedVectors reads the vectors, whose first row names the columns.
func loadUnifiedVectors(t *testing.T) []unifiedVector {
	t.Helper()

	raw, err := os.ReadFile("data/unified_sighash.json")
	require.NoError(t, err)

	var rows []json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &rows))
	require.Greater(t, len(rows), 1)

	var header []string
	require.NoError(t, json.Unmarshal(rows[0], &header))
	require.Equal(t, []string{
		"scriptCode", "rawTx", "inIdx", "hashType", "scriptType",
		"spentOutputs", "sighash",
	}, header)

	vectors := make([]unifiedVector, 0, len(rows)-1)
	for _, row := range rows[1:] {
		var cols []json.RawMessage
		require.NoError(t, json.Unmarshal(row, &cols))
		require.Len(t, cols, len(header))

		var v unifiedVector
		require.NoError(t, json.Unmarshal(cols[0], &v.ScriptCode))
		require.NoError(t, json.Unmarshal(cols[1], &v.RawTx))
		require.NoError(t, json.Unmarshal(cols[2], &v.InIdx))
		require.NoError(t, json.Unmarshal(cols[3], &v.HashType))
		require.NoError(t, json.Unmarshal(cols[4], &v.ScriptType))
		require.NoError(t, json.Unmarshal(cols[5], &v.SpentOutputs))
		require.NoError(t, json.Unmarshal(cols[6], &v.SigHash))
		vectors = append(vectors, v)
	}

	return vectors
}

// unifiedVectorDigest computes the digest a vector describes.
func unifiedVectorDigest(t *testing.T, v unifiedVector) []byte {
	t.Helper()

	txBytes, err := hex.DecodeString(v.RawTx)
	require.NoError(t, err)
	var tx wire.MsgTx
	require.NoError(t, tx.Deserialize(bytes.NewReader(txBytes)))
	require.Len(t, v.SpentOutputs, len(tx.TxIn))

	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(tx.TxIn))
	for i, in := range tx.TxIn {
		amount, ok := v.SpentOutputs[i][0].(float64)
		require.True(t, ok)
		pkScript, err := hex.DecodeString(v.SpentOutputs[i][1].(string))
		require.NoError(t, err)
		prevOuts[in.PreviousOutPoint] = wire.NewTxOut(int64(amount), pkScript)
	}
	fetcher := NewMultiPrevOutFetcher(prevOuts)

	scriptCode, err := hex.DecodeString(v.ScriptCode)
	require.NoError(t, err)

	var opts []UnifiedSigHashOption
	switch UnifiedScriptType(v.ScriptType) {
	case UnifiedScriptBare, UnifiedScriptWitnessV0:
		opts = append(opts, WithUnifiedScriptCode(scriptCode))
	case UnifiedScriptTapscript:
		leafHash := NewBaseTapLeaf(scriptCode).TapHash()
		opts = append(opts, WithUnifiedTapLeaf(leafHash[:], blankCodeSepValue))
	}

	digest, err := CalcUnifiedSignatureHash(
		&tx, v.InIdx, UnifiedScriptType(v.ScriptType),
		SigHashType(v.HashType), fetcher, opts...,
	)
	require.NoError(t, err)

	return digest
}

// TestUnifiedSigHashVectors: every one of Knots' vectors, over all four
// script types, reproduces byte for byte.
func TestUnifiedSigHashVectors(t *testing.T) {
	t.Parallel()

	vectors := loadUnifiedVectors(t)
	require.Len(t, vectors, 166)

	kinds := make(map[int]int)
	for i, v := range vectors {
		kinds[v.ScriptType]++
		digest := unifiedVectorDigest(t, v)
		require.Equal(t, v.SigHash, hex.EncodeToString(digest),
			"vector %d (script type %d, hash type 0x%x)", i,
			v.ScriptType, v.HashType)
	}
	for _, kind := range []UnifiedScriptType{
		UnifiedScriptBare, UnifiedScriptWitnessV0, UnifiedScriptTaproot,
		UnifiedScriptTapscript,
	} {
		require.Greater(t, kinds[int(kind)], 0, "no vector of type %d", kind)
	}
}

// TestUnifiedSigHashScriptTypeSeparatesDomains: the same spend hashed under
// another script type gives another digest.
func TestUnifiedSigHashScriptTypeSeparatesDomains(t *testing.T) {
	t.Parallel()

	for _, v := range loadUnifiedVectors(t) {
		if UnifiedScriptType(v.ScriptType) != UnifiedScriptBare {
			continue
		}
		wrong := v
		wrong.ScriptType = int(UnifiedScriptWitnessV0)
		require.NotEqual(t, v.SigHash,
			hex.EncodeToString(unifiedVectorDigest(t, wrong)))
		break
	}
}

// TestCheckUnifiedSigHash pins the hash type rules: the bit must be set;
// bare and witness v0 read the byte as the legacy algorithm does; taproot
// keeps BIP341's reading and cannot carry the bit on SIGHASH_DEFAULT.
func TestCheckUnifiedSigHash(t *testing.T) {
	t.Parallel()

	type result struct {
		base SigHashType
		acp  bool
		ok   bool
	}
	tests := []struct {
		hashType   SigHashType
		scriptType UnifiedScriptType
		want       result
	}{
		// The bit must be set, whatever the script type.
		{SigHashAll, UnifiedScriptBare, result{ok: false}},
		{SigHashAll, UnifiedScriptTaproot, result{ok: false}},
		{0x81, UnifiedScriptWitnessV0, result{ok: false}},

		// Legacy reading for bare and witness v0.
		{0x21, UnifiedScriptBare, result{SigHashAll, false, true}},
		{0x22, UnifiedScriptWitnessV0, result{SigHashNone, false, true}},
		{0xa3, UnifiedScriptWitnessV0, result{SigHashSingle, true, true}},
		{0x20, UnifiedScriptBare, result{0, false, true}},
		{0xff, UnifiedScriptWitnessV0, result{0x1f, true, true}},
		{0x3f, UnifiedScriptBare, result{0x1f, false, true}},

		// BIP341 reading for taproot and tapscript.
		{0x21, UnifiedScriptTaproot, result{SigHashAll, false, true}},
		{0xa2, UnifiedScriptTapscript, result{SigHashNone, true, true}},
		{0xa3, UnifiedScriptTaproot, result{SigHashSingle, true, true}},
		{0x20, UnifiedScriptTaproot, result{ok: false}},
		{0x24, UnifiedScriptTaproot, result{ok: false}},
		{0x3f, UnifiedScriptTapscript, result{ok: false}},
		{0x61, UnifiedScriptTaproot, result{ok: false}},

		// Wider than a byte is a caller error.
		{0x121, UnifiedScriptBare, result{ok: false}},
	}
	for _, test := range tests {
		base, acp, err := checkUnifiedSigHash(test.hashType, test.scriptType)
		if !test.want.ok {
			require.Error(t, err, "0x%x/%d", test.hashType, test.scriptType)
			continue
		}
		require.NoError(t, err, "0x%x/%d", test.hashType, test.scriptType)
		require.Equal(t, test.want.base, base)
		require.Equal(t, test.want.acp, acp)
	}

	_, _, err := checkUnifiedSigHash(0x21, UnifiedScriptType(7))
	require.Error(t, err)
}

// TestUnifiedSigHashRequirements: the digest refuses what it cannot commit
// to.
func TestUnifiedSigHashRequirements(t *testing.T) {
	t.Parallel()

	tx := wire.NewMsgTx(2)
	prev := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}
	tx.AddTxIn(wire.NewTxIn(&prev, nil, nil))
	fetcher := NewCannedPrevOutputFetcher([]byte{OP_TRUE}, 1000)
	code := WithUnifiedScriptCode([]byte{OP_TRUE})

	// No outputs at all is fine for ALL and NONE, not for SINGLE.
	_, err := CalcUnifiedSignatureHash(
		tx, 0, UnifiedScriptBare, 0x21, fetcher, code,
	)
	require.NoError(t, err)
	_, err = CalcUnifiedSignatureHash(
		tx, 0, UnifiedScriptBare, 0x23, fetcher, code,
	)
	require.ErrorContains(t, err, "SIGHASH_SINGLE")

	// A script code is required for bare and witness v0, a leaf hash for
	// tapscript, and the spent outputs always.
	_, err = CalcUnifiedSignatureHash(
		tx, 0, UnifiedScriptWitnessV0, 0x21, fetcher,
	)
	require.ErrorContains(t, err, "script code")
	_, err = CalcUnifiedSignatureHash(
		tx, 0, UnifiedScriptTapscript, 0x21, fetcher,
	)
	require.ErrorContains(t, err, "tapleaf")
	_, err = CalcUnifiedSignatureHash(
		tx, 0, UnifiedScriptBare, 0x21, nil, code,
	)
	require.ErrorContains(t, err, "PrevOutputFetcher")
	_, err = CalcUnifiedSignatureHash(
		tx, 0, UnifiedScriptBare, 0x21,
		NewMultiPrevOutFetcher(nil), code,
	)
	require.ErrorContains(t, err, "unknown")
	_, err = CalcUnifiedSignatureHash(
		tx, 1, UnifiedScriptBare, 0x21, fetcher, code,
	)
	require.ErrorContains(t, err, "txins")
}

// unifiedSpend is a transaction spending one output of each kind the node
// signs alone, with the key and script material needed to sign and verify
// each input.
type unifiedSpend struct {
	tx      *wire.MsgTx
	prevs   map[wire.OutPoint]*wire.TxOut
	fetcher *MultiPrevOutFetcher

	key         *btcec.PrivateKey
	p2pkh       []byte
	p2wpkh      []byte
	p2wsh       []byte
	witnessScr  []byte
	p2tr        []byte
	p2trScript  []byte
	tapLeaf     TapLeaf
	ctrlBlock   []byte
	inputAmount int64
}

const (
	unifiedInP2PKH = iota
	unifiedInP2WPKH
	unifiedInP2WSH
	unifiedInP2TR
	unifiedInTapscript
)

func newUnifiedSpend(t *testing.T) *unifiedSpend {
	t.Helper()

	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pub := key.PubKey()
	params := &chaincfg.MainNetParams

	s := &unifiedSpend{key: key, inputAmount: 100_000}

	pkh, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pub.SerializeCompressed()), params,
	)
	require.NoError(t, err)
	s.p2pkh, err = PayToAddrScript(pkh)
	require.NoError(t, err)

	wpkh, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pub.SerializeCompressed()), params,
	)
	require.NoError(t, err)
	s.p2wpkh, err = PayToAddrScript(wpkh)
	require.NoError(t, err)

	s.witnessScr, err = NewScriptBuilder().
		AddData(pub.SerializeCompressed()).AddOp(OP_CHECKSIG).Script()
	require.NoError(t, err)
	wsh, err := btcutil.NewAddressWitnessScriptHash(
		chainhash.HashB(s.witnessScr), params,
	)
	require.NoError(t, err)
	s.p2wsh, err = PayToAddrScript(wsh)
	require.NoError(t, err)

	s.p2tr, err = PayToTaprootScript(ComputeTaprootKeyNoScript(pub))
	require.NoError(t, err)

	leafScript, err := NewScriptBuilder().
		AddData(schnorrPubKey(pub)).AddOp(OP_CHECKSIG).Script()
	require.NoError(t, err)
	s.tapLeaf = NewBaseTapLeaf(leafScript)
	tree := AssembleTaprootScriptTree(s.tapLeaf)
	root := tree.RootNode.TapHash()
	s.p2trScript, err = PayToTaprootScript(
		ComputeTaprootOutputKey(pub, root[:]),
	)
	require.NoError(t, err)
	ctrl := tree.LeafMerkleProofs[0].ToControlBlock(pub)
	s.ctrlBlock, err = ctrl.ToBytes()
	require.NoError(t, err)

	s.tx = wire.NewMsgTx(2)
	s.prevs = make(map[wire.OutPoint]*wire.TxOut)
	for i, pkScript := range [][]byte{
		s.p2pkh, s.p2wpkh, s.p2wsh, s.p2tr, s.p2trScript,
	} {
		op := wire.OutPoint{Hash: chainhash.Hash{byte(i + 1)}, Index: uint32(i)}
		s.tx.AddTxIn(wire.NewTxIn(&op, nil, nil))
		s.prevs[op] = wire.NewTxOut(s.inputAmount, pkScript)
	}
	// One output per input, so SIGHASH_SINGLE has a partner for every
	// input.
	for range s.tx.TxIn {
		s.tx.AddTxOut(wire.NewTxOut(s.inputAmount-200, s.p2wpkh))
	}
	s.fetcher = NewMultiPrevOutFetcher(s.prevs)

	return s
}

// schnorrPubKey returns the x-only encoding of a public key.
func schnorrPubKey(pub *btcec.PublicKey) []byte {
	return pub.SerializeCompressed()[1:]
}

// sign fills the witness or signature script of every input with the given
// hash type (taproot inputs use taprootHashType).
func (s *unifiedSpend) sign(t *testing.T, hashType,
	taprootHashType SigHashType) {

	t.Helper()
	sigHashes := NewTxSigHashes(s.tx, s.fetcher)

	// P2PKH: the bare path has no signing helper that knows the spent
	// outputs, so the digest is computed and signed by hand.
	var digest []byte
	var err error
	if hashType&SigHashUnified != 0 {
		digest, err = CalcUnifiedSignatureHash(
			s.tx, unifiedInP2PKH, UnifiedScriptBare, hashType, s.fetcher,
			WithUnifiedScriptCode(s.p2pkh),
		)
		require.NoError(t, err)
	} else {
		digest = calcSignatureHash(s.p2pkh, hashType, s.tx, unifiedInP2PKH)
	}
	sig := append(ecdsa.Sign(s.key, digest).Serialize(), byte(hashType))
	s.tx.TxIn[unifiedInP2PKH].SignatureScript, err = NewScriptBuilder().
		AddData(sig).AddData(s.key.PubKey().SerializeCompressed()).Script()
	require.NoError(t, err)

	s.tx.TxIn[unifiedInP2WPKH].Witness, err = WitnessSignature(
		s.tx, sigHashes, unifiedInP2WPKH, s.inputAmount, s.p2wpkh,
		hashType, s.key, true,
	)
	require.NoError(t, err)

	sig, err = RawTxInWitnessSignature(
		s.tx, sigHashes, unifiedInP2WSH, s.inputAmount, s.witnessScr,
		hashType, s.key,
	)
	require.NoError(t, err)
	s.tx.TxIn[unifiedInP2WSH].Witness = wire.TxWitness{sig, s.witnessScr}

	s.tx.TxIn[unifiedInP2TR].Witness, err = TaprootWitnessSignature(
		s.tx, sigHashes, unifiedInP2TR, s.inputAmount, s.p2tr,
		taprootHashType, s.key,
	)
	require.NoError(t, err)

	sig, err = RawTxInTapscriptSignature(
		s.tx, sigHashes, unifiedInTapscript, s.inputAmount, s.p2trScript,
		s.tapLeaf, taprootHashType, s.key,
	)
	require.NoError(t, err)
	s.tx.TxIn[unifiedInTapscript].Witness = wire.TxWitness{
		sig, s.tapLeaf.Script, s.ctrlBlock,
	}
}

// verify runs the script engine over every input with the given fetcher.
func (s *unifiedSpend) verify(t *testing.T, fetcher PrevOutputFetcher) error {
	t.Helper()
	sigHashes := NewTxSigHashes(s.tx, fetcher)
	for i, in := range s.tx.TxIn {
		prev := fetcher.FetchPrevOutput(in.PreviousOutPoint)
		vm, err := NewEngine(
			prev.PkScript, s.tx, i, StandardVerifyFlags, nil,
			sigHashes, prev.Value, fetcher,
		)
		require.NoError(t, err)
		if err := vm.Execute(); err != nil {
			return err
		}
	}
	return nil
}

// TestUnifiedSigHashRoundTrip: signatures made with the opt-in bit verify
// under the engine for every script type the node signs alone, the taproot
// ones are 65 bytes, and the same signatures fail once the bit is dropped
// or a sibling input's amount is misreported.
func TestUnifiedSigHashRoundTrip(t *testing.T) {
	t.Parallel()

	for _, hashType := range []SigHashType{
		SigHashAll | SigHashUnified,
		SigHashSingle | SigHashAnyOneCanPay | SigHashUnified,
	} {
		s := newUnifiedSpend(t)
		s.sign(t, hashType, hashType)
		require.NoError(t, s.verify(t, s.fetcher), "hash type 0x%x", hashType)

		// Taproot signatures always carry the byte.
		require.Len(t, s.tx.TxIn[unifiedInP2TR].Witness[0], 65)
		require.Equal(t, byte(hashType),
			s.tx.TxIn[unifiedInP2TR].Witness[0][64])
		require.Len(t, s.tx.TxIn[unifiedInTapscript].Witness[0], 65)

		// A witness v0 signature whose last byte loses the bit no longer
		// verifies: the byte is committed to.
		sig := s.tx.TxIn[unifiedInP2WPKH].Witness[0]
		sig[len(sig)-1] &^= byte(SigHashUnified)
		require.Error(t, s.verify(t, s.fetcher))
		sig[len(sig)-1] |= byte(SigHashUnified)
		require.NoError(t, s.verify(t, s.fetcher))

		if hashType&SigHashAnyOneCanPay != 0 {
			continue
		}

		// Misreport a sibling input's amount: every input commits to
		// every spent output, so the whole transaction fails.
		lying := make(map[wire.OutPoint]*wire.TxOut, len(s.prevs))
		for op, out := range s.prevs {
			lying[op] = wire.NewTxOut(out.Value, out.PkScript)
		}
		lying[s.tx.TxIn[unifiedInP2WSH].PreviousOutPoint].Value++
		require.Error(t, s.verify(t, NewMultiPrevOutFetcher(lying)))
	}
}

// TestUnifiedSigHashLegacyStillVerifies: the opt-in bit is opt-in; the
// engine keeps accepting legacy, BIP143 and BIP341 signatures.
func TestUnifiedSigHashLegacyStillVerifies(t *testing.T) {
	t.Parallel()

	s := newUnifiedSpend(t)
	s.sign(t, SigHashAll, SigHashDefault)
	require.NoError(t, s.verify(t, s.fetcher))
	require.Len(t, s.tx.TxIn[unifiedInP2TR].Witness[0], 64)
}

// TestUnifiedSigHashTaprootRefusesDefault: a taproot signature cannot carry
// the bit on SIGHASH_DEFAULT, at signing and at verification.
func TestUnifiedSigHashTaprootRefusesDefault(t *testing.T) {
	t.Parallel()

	s := newUnifiedSpend(t)
	sigHashes := NewTxSigHashes(s.tx, s.fetcher)
	_, err := TaprootWitnessSignature(
		s.tx, sigHashes, unifiedInP2TR, s.inputAmount, s.p2tr,
		SigHashUnified, s.key,
	)
	require.Error(t, err)
	_, err = RawTxInTapscriptSignature(
		s.tx, sigHashes, unifiedInTapscript, s.inputAmount, s.p2trScript,
		s.tapLeaf, SigHashUnified, s.key,
	)
	require.Error(t, err)

	// A forged 65-byte signature ending in the bare bit is rejected.
	s.sign(t, SigHashAll|SigHashUnified, SigHashAll|SigHashUnified)
	sig := s.tx.TxIn[unifiedInP2TR].Witness[0]
	sig[64] = byte(SigHashUnified)
	require.Error(t, s.verify(t, s.fetcher))
}

// TestUnifiedSigHashStrictEncoding: policy treats the opt-in bit as
// defined, so 0x21 and 0xa1 pass strict hash type encoding while a byte
// naming no output commitment still fails.
func TestUnifiedSigHashStrictEncoding(t *testing.T) {
	t.Parallel()

	vm := &Engine{flags: ScriptVerifyStrictEncoding | ScriptVerifyUnifiedSigHash}
	require.NoError(t, vm.checkHashTypeEncoding(0x21))
	require.NoError(t, vm.checkHashTypeEncoding(0xa3))
	require.Error(t, vm.checkHashTypeEncoding(0x20))
	require.Error(t, vm.checkHashTypeEncoding(0x24))
	require.Error(t, vm.checkHashTypeEncoding(0x04))

	// Without the fork flag the bit is undefined, as Core has it.
	core := &Engine{flags: ScriptVerifyStrictEncoding}
	require.Error(t, core.checkHashTypeEncoding(0x21))
	require.NoError(t, core.checkHashTypeEncoding(0x01))
}

// TestUnifiedSigHashRefusesCannedSiblings: a canned fetcher is exact for one
// input and for ANYONECANPAY, and refused for the siblings of a multi-input
// transaction rather than hashed wrongly.
func TestUnifiedSigHashRefusesCannedSiblings(t *testing.T) {
	t.Parallel()

	s := newUnifiedSpend(t)
	canned := NewCannedPrevOutputFetcher(s.p2wpkh, s.inputAmount)
	code := WithUnifiedScriptCode(witnessV0ScriptCode(s.p2wpkh))

	_, err := CalcUnifiedSignatureHash(
		s.tx, unifiedInP2WPKH, UnifiedScriptWitnessV0, 0x21, canned, code,
	)
	require.ErrorContains(t, err, "canned")
	_, err = CalcUnifiedSignatureHash(
		s.tx, unifiedInP2WPKH, UnifiedScriptWitnessV0, 0xa1, canned, code,
	)
	require.NoError(t, err)

	// The signing helpers with a midstate built from a canned fetcher
	// refuse too, instead of returning a signature nobody accepts.
	cannedHashes := NewTxSigHashes(s.tx, canned)
	_, err = RawTxInWitnessSignature(
		s.tx, cannedHashes, unifiedInP2WPKH, s.inputAmount, s.p2wpkh,
		0x21, s.key,
	)
	require.Error(t, err)
	_, err = TaprootWitnessSignature(
		s.tx, cannedHashes, unifiedInP2TR, s.inputAmount, s.p2tr, 0x21,
		s.key,
	)
	require.Error(t, err)

	// A single-input transaction is exactly what a canned fetcher
	// describes.
	single := wire.NewMsgTx(2)
	single.AddTxIn(wire.NewTxIn(&s.tx.TxIn[unifiedInP2TR].PreviousOutPoint, nil, nil))
	single.AddTxOut(wire.NewTxOut(s.inputAmount-200, s.p2wpkh))
	singleCanned := NewCannedPrevOutputFetcher(s.p2tr, s.inputAmount)
	_, err = TaprootWitnessSignature(
		single, NewTxSigHashes(single, singleCanned), 0, s.inputAmount,
		s.p2tr, 0x21, s.key,
	)
	require.NoError(t, err)
}

// TestUnifiedSigHashGatedByFlag: without ScriptVerifyUnifiedSigHash the
// engine reads the byte as it did before the fork, so an opted-in
// signature fails, and StandardVerifyFlags carries the flag.
func TestUnifiedSigHashGatedByFlag(t *testing.T) {
	t.Parallel()

	require.NotZero(t, StandardVerifyFlags&ScriptVerifyUnifiedSigHash)

	s := newUnifiedSpend(t)
	s.sign(t, SigHashAll|SigHashUnified, SigHashAll|SigHashUnified)
	flags := StandardVerifyFlags &^ ScriptVerifyUnifiedSigHash
	sigHashes := NewTxSigHashes(s.tx, s.fetcher)
	for i, in := range s.tx.TxIn {
		prev := s.fetcher.FetchPrevOutput(in.PreviousOutPoint)
		vm, err := NewEngine(
			prev.PkScript, s.tx, i, flags, nil, sigHashes, prev.Value,
			s.fetcher,
		)
		require.NoError(t, err)
		require.Error(t, vm.Execute(), "input %d verified without the flag", i)
	}

	// The exported key-spend check keeps BIP341's rules alone.
	require.Error(t, VerifyTaprootKeySpend(
		s.p2tr[2:], s.tx.TxIn[unifiedInP2TR].Witness[0], s.tx,
		unifiedInP2TR, s.fetcher, sigHashes, nil,
	))
}

// TestTxSigHashesUnknownPrevOut: a midstate can be built for a transaction
// whose spent outputs the fetcher does not all know; the unified digest
// then refuses rather than hashing garbage.
func TestTxSigHashesUnknownPrevOut(t *testing.T) {
	t.Parallel()

	s := newUnifiedSpend(t)
	empty := NewMultiPrevOutFetcher(nil)
	require.NotPanics(t, func() { NewTxSigHashes(s.tx, empty) })

	_, err := RawTxInWitnessSignature(
		s.tx, NewTxSigHashes(s.tx, empty), unifiedInP2WPKH, s.inputAmount,
		s.p2wpkh, SigHashAll|SigHashUnified, s.key,
	)
	require.ErrorContains(t, err, "unknown")
}
