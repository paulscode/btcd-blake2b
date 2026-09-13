// Copyright (c) 2026 The Lightning Fork developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// SigHashUnified is the opt-in bit for the unified signature hash of the
// Bitcoin BLAKE2b chain. A signature whose hash type carries it commits to
// the message computed by CalcUnifiedSignatureHash instead of the legacy,
// BIP143 or BIP341 message for its script type. The bit is committed to by
// the signature, and a node that does not know the algorithm rejects the
// signature outright, which is what makes an opted-in transaction
// unreplayable on the SHA256d chain.
const SigHashUnified SigHashType = 0x20

// unifiedSigHashTag is the BIP340 tag of the unified signature hash.
var unifiedSigHashTag = []byte("UnifiedSighash")

// UnifiedScriptType is the byte the unified message carries to separate the
// four kinds of spend, so that a signature made for one can never be valid
// for another.
type UnifiedScriptType byte

const (
	// UnifiedScriptBare covers bare and P2SH inputs.
	UnifiedScriptBare UnifiedScriptType = 0

	// UnifiedScriptWitnessV0 covers P2WPKH, P2WSH and their P2SH-nested
	// forms.
	UnifiedScriptWitnessV0 UnifiedScriptType = 1

	// UnifiedScriptTaproot covers taproot key-path spends.
	UnifiedScriptTaproot UnifiedScriptType = 2

	// UnifiedScriptTapscript covers tapscript spends.
	UnifiedScriptTapscript UnifiedScriptType = 3
)

// unifiedSigHashOptions carries the per-spend data the unified message needs
// that is not in the transaction itself.
type unifiedSigHashOptions struct {
	scriptCode []byte

	// annexHash is sha256(compactSize(annex) || annex), or nil when the
	// spend carries no annex.
	annexHash   []byte
	tapLeafHash []byte
	codeSepPos  uint32
}

// UnifiedSigHashOption is a functional option for CalcUnifiedSignatureHash.
type UnifiedSigHashOption func(*unifiedSigHashOptions)

// WithUnifiedScriptCode sets the script code of a bare or witness v0 spend:
// the scriptPubKey of a bare input, the redeem script of P2SH, the witness
// script of P2WSH, or the implied P2PKH script of P2WPKH, cut after the last
// executed OP_CODESEPARATOR where there is one.
func WithUnifiedScriptCode(scriptCode []byte) UnifiedSigHashOption {
	return func(o *unifiedSigHashOptions) {
		o.scriptCode = scriptCode
	}
}

// WithUnifiedAnnex sets the annex of a taproot or tapscript spend.
func WithUnifiedAnnex(annex []byte) UnifiedSigHashOption {
	return func(o *unifiedSigHashOptions) {
		var b bytes.Buffer
		_ = wire.WriteVarBytes(&b, 0, annex)
		h := sha256.Sum256(b.Bytes())
		o.annexHash = h[:]
	}
}

// withUnifiedAnnexHash sets the annex commitment directly, for the taproot
// path that already holds it in that form.
func withUnifiedAnnexHash(annexHash []byte) UnifiedSigHashOption {
	return func(o *unifiedSigHashOptions) {
		o.annexHash = annexHash
	}
}

// WithUnifiedTapLeaf marks the spend as a tapscript spend of the leaf with
// the given BIP341 leaf hash, at the given code separator position
// (blankCodeSepValue, 0xffffffff, when no OP_CODESEPARATOR has executed).
func WithUnifiedTapLeaf(tapLeafHash []byte,
	codeSepPos uint32) UnifiedSigHashOption {

	return func(o *unifiedSigHashOptions) {
		o.tapLeafHash = tapLeafHash
		o.codeSepPos = codeSepPos
	}
}

// checkUnifiedSigHash validates a hash type for the unified algorithm and
// splits it into the base output-commitment type and the ANYONECANPAY flag.
//
// Each script type keeps the reading it has today. Bare and witness v0 take
// the legacy one, where anything that is not NONE or SINGLE signs every
// output and the remaining bits are committed to but carry no meaning.
// Taproot and tapscript keep BIP341's, which refuses a hash type it does not
// define; and since SIGHASH_DEFAULT means "no hash type byte at all", it can
// never carry the bit, so an opted-in taproot signature is always 65 bytes.
func checkUnifiedSigHash(hashType SigHashType,
	scriptType UnifiedScriptType) (SigHashType, bool, error) {

	// Consensus only ever sees the last byte of a signature, so anything
	// wider is a caller error rather than a hash type.
	if hashType > 0xff {
		return 0, false, fmt.Errorf("hash type 0x%x does not fit the "+
			"signature's hash type byte", hashType)
	}
	if hashType&SigHashUnified == 0 {
		return 0, false, fmt.Errorf("hash type 0x%x does not carry "+
			"SIGHASH_UNIFIED", hashType)
	}

	anyoneCanPay := hashType&SigHashAnyOneCanPay != 0
	base := hashType & sigHashMask

	switch scriptType {
	case UnifiedScriptBare, UnifiedScriptWitnessV0:
		return base, anyoneCanPay, nil

	case UnifiedScriptTaproot, UnifiedScriptTapscript:
		defined := SigHashType(sigHashMask) | SigHashUnified |
			SigHashAnyOneCanPay
		if hashType&^defined != 0 {
			return 0, false, fmt.Errorf("hash type 0x%x sets bits "+
				"taproot does not define", hashType)
		}
		switch base {
		case SigHashAll, SigHashNone, SigHashSingle:
			return base, anyoneCanPay, nil
		}
		return 0, false, fmt.Errorf("hash type 0x%x is not a taproot "+
			"hash type (SIGHASH_DEFAULT cannot carry SIGHASH_UNIFIED)",
			hashType)

	default:
		return 0, false, fmt.Errorf("unknown unified script type %d",
			scriptType)
	}
}

// CalcUnifiedSignatureHash computes the unified signature hash of input idx
// of tx: TaggedHash("UnifiedSighash", message), where the message is laid
// out as BIP341 lays out its own, commits to every spent output's value and
// scriptPubKey, and carries the script type so that a signature made for
// one kind of spend is never valid for another. The hash type must carry
// SigHashUnified. prevOutFetcher must know every input's spent output, or
// only this input's under ANYONECANPAY. Bare and witness v0 spends need
// WithUnifiedScriptCode; tapscript spends need WithUnifiedTapLeaf.
func CalcUnifiedSignatureHash(tx *wire.MsgTx, idx int,
	scriptType UnifiedScriptType, hashType SigHashType,
	prevOutFetcher PrevOutputFetcher,
	sigHashOpts ...UnifiedSigHashOption) ([]byte, error) {

	opts := &unifiedSigHashOptions{codeSepPos: blankCodeSepValue}
	for _, opt := range sigHashOpts {
		opt(opts)
	}

	if idx < 0 || idx >= len(tx.TxIn) {
		return nil, fmt.Errorf("idx %d but %d txins", idx, len(tx.TxIn))
	}

	base, anyoneCanPay, err := checkUnifiedSigHash(hashType, scriptType)
	if err != nil {
		return nil, err
	}

	switch scriptType {
	case UnifiedScriptBare, UnifiedScriptWitnessV0:
		if opts.scriptCode == nil {
			return nil, fmt.Errorf("unified script type %d needs a "+
				"script code", scriptType)
		}
	case UnifiedScriptTapscript:
		if len(opts.tapLeafHash) != chainhash.HashSize {
			return nil, fmt.Errorf("tapscript spends need a 32-byte " +
				"tapleaf hash")
		}
	}

	if prevOutFetcher == nil {
		return nil, fmt.Errorf("the unified signature hash needs the " +
			"spent outputs, but no PrevOutputFetcher was given")
	}
	spentOutput := func(i int) (*wire.TxOut, error) {
		out := prevOutFetcher.FetchPrevOutput(tx.TxIn[i].PreviousOutPoint)
		if out == nil {
			return nil, fmt.Errorf("the spent output of input %d (%v) "+
				"is unknown, and the unified signature hash commits "+
				"to it", i, tx.TxIn[i].PreviousOutPoint)
		}
		return out, nil
	}

	var msg bytes.Buffer
	msg.WriteByte(0x00)
	msg.WriteByte(byte(hashType))
	var scratch [8]byte
	binary.LittleEndian.PutUint32(scratch[:], uint32(tx.Version))
	msg.Write(scratch[:4])

	// The locktime is committed to as five bytes: four run out in 2106,
	// and widening the field later must not change this message.
	binary.LittleEndian.PutUint32(scratch[:], tx.LockTime)
	msg.Write(scratch[:4])
	msg.WriteByte(0x00)

	if !anyoneCanPay {
		var prevouts, amounts, scripts, sequences bytes.Buffer
		for i, in := range tx.TxIn {
			out, err := spentOutput(i)
			if err != nil {
				return nil, err
			}
			prevouts.Write(in.PreviousOutPoint.Hash[:])
			binary.LittleEndian.PutUint32(
				scratch[:], in.PreviousOutPoint.Index,
			)
			prevouts.Write(scratch[:4])
			binary.LittleEndian.PutUint64(scratch[:], uint64(out.Value))
			amounts.Write(scratch[:])
			if err := wire.WriteVarBytes(
				&scripts, 0, out.PkScript,
			); err != nil {
				return nil, err
			}
			binary.LittleEndian.PutUint32(scratch[:], in.Sequence)
			sequences.Write(scratch[:4])
		}
		for _, agg := range [][]byte{
			prevouts.Bytes(), amounts.Bytes(), scripts.Bytes(),
			sequences.Bytes(),
		} {
			h := sha256.Sum256(agg)
			msg.Write(h[:])
		}
	}

	if base != SigHashNone && base != SigHashSingle {
		var outputs bytes.Buffer
		for _, out := range tx.TxOut {
			if err := wire.WriteTxOut(&outputs, 0, 0, out); err != nil {
				return nil, err
			}
		}
		h := sha256.Sum256(outputs.Bytes())
		msg.Write(h[:])
	}

	msg.WriteByte(byte(scriptType))

	if anyoneCanPay {
		in := tx.TxIn[idx]
		out, err := spentOutput(idx)
		if err != nil {
			return nil, err
		}
		msg.Write(in.PreviousOutPoint.Hash[:])
		binary.LittleEndian.PutUint32(scratch[:], in.PreviousOutPoint.Index)
		msg.Write(scratch[:4])
		if err := wire.WriteTxOut(&msg, 0, 0, out); err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint32(scratch[:], in.Sequence)
		msg.Write(scratch[:4])
	} else {
		binary.LittleEndian.PutUint32(scratch[:], uint32(idx))
		msg.Write(scratch[:4])
	}

	switch scriptType {
	case UnifiedScriptBare, UnifiedScriptWitnessV0:
		if err := wire.WriteVarBytes(&msg, 0, opts.scriptCode); err != nil {
			return nil, err
		}

	default:
		if opts.annexHash == nil {
			msg.WriteByte(0x00)
		} else {
			msg.WriteByte(0x01)
			msg.Write(opts.annexHash)
		}
	}

	if base == SigHashSingle {
		if idx >= len(tx.TxOut) {
			return nil, fmt.Errorf("SIGHASH_SINGLE on input %d, but the "+
				"transaction has only %d outputs", idx, len(tx.TxOut))
		}
		var output bytes.Buffer
		if err := wire.WriteTxOut(&output, 0, 0, tx.TxOut[idx]); err != nil {
			return nil, err
		}
		h := sha256.Sum256(output.Bytes())
		msg.Write(h[:])
	}

	if scriptType == UnifiedScriptTapscript {
		msg.Write(opts.tapLeafHash)
		msg.WriteByte(0x00)
		binary.LittleEndian.PutUint32(scratch[:], opts.codeSepPos)
		msg.Write(scratch[:4])
	}

	return chainhash.TaggedHash(unifiedSigHashTag, msg.Bytes())[:], nil
}

// witnessV0ScriptCode returns the script code of a witness v0 spend: the
// implied P2PKH script for a P2WPKH program, the script itself otherwise.
func witnessV0ScriptCode(subScript []byte) []byte {
	if !isWitnessPubKeyHashScript(subScript) {
		return subScript
	}
	code := make([]byte, 0, 25)
	code = append(code, OP_DUP, OP_HASH160, OP_DATA_20)
	code = append(code, extractWitnessPubKeyHash(subScript)...)
	return append(code, OP_EQUALVERIFY, OP_CHECKSIG)
}

// calcWitnessSignatureHashRaw computes the digest a witness v0 signature
// commits to: the unified message when the hash type opts in, BIP143's
// otherwise. The unified message needs every spent output, which the
// midstate's fetcher knows.
func calcWitnessSignatureHashRaw(subScript []byte, sigHashes *TxSigHashes,
	hashType SigHashType, tx *wire.MsgTx, idx int, amt int64) ([]byte, error) {

	if hashType&SigHashUnified != 0 {
		var fetcher PrevOutputFetcher
		if sigHashes != nil {
			fetcher = sigHashes.prevOutFetcher
		}
		return CalcUnifiedSignatureHash(
			tx, idx, UnifiedScriptWitnessV0, hashType, fetcher,
			WithUnifiedScriptCode(witnessV0ScriptCode(subScript)),
		)
	}

	return calcWitnessSignatureHashBIP143(
		subScript, sigHashes, hashType, tx, idx, amt,
	)
}

// calcTaprootSignatureHashRaw computes the digest a taproot or tapscript
// signature commits to: the unified message when the hash type opts in,
// with the same leaf and annex context, BIP341's otherwise.
func calcTaprootSignatureHashRaw(sigHashes *TxSigHashes, hType SigHashType,
	tx *wire.MsgTx, idx int, prevOutFetcher PrevOutputFetcher,
	sigHashOpts ...TaprootSigHashOption) ([]byte, error) {

	if hType&SigHashUnified == 0 {
		return calcTaprootSignatureHashBIP341(
			sigHashes, hType, tx, idx, prevOutFetcher, sigHashOpts...,
		)
	}

	opts := defaultTaprootSighashOptions()
	for _, sigHashOpt := range sigHashOpts {
		sigHashOpt(opts)
	}

	scriptType := UnifiedScriptTaproot
	var unifiedOpts []UnifiedSigHashOption
	if opts.extFlag == tapscriptSighashExtFlag {
		scriptType = UnifiedScriptTapscript
		unifiedOpts = append(unifiedOpts, WithUnifiedTapLeaf(
			opts.tapLeafHash, opts.codeSepPos,
		))
	}
	if opts.annexHash != nil {
		unifiedOpts = append(
			unifiedOpts, withUnifiedAnnexHash(opts.annexHash),
		)
	}

	return CalcUnifiedSignatureHash(
		tx, idx, scriptType, hType, prevOutFetcher, unifiedOpts...,
	)
}

// witnessSigHash computes the digest a witness v0 signature checked by the
// engine commits to. Without ScriptVerifyUnifiedSigHash the opt-in bit is
// just another bit of the hash type byte, as it was before the fork: the
// digest is BIP143's, computed over the byte as given.
func (vm *Engine) witnessSigHash(subScript []byte, sigHashes *TxSigHashes,
	hashType SigHashType) ([]byte, error) {

	if hashType&SigHashUnified != 0 &&
		!vm.hasFlag(ScriptVerifyUnifiedSigHash) {

		return calcWitnessSignatureHashBIP143(
			subScript, sigHashes, hashType, &vm.tx, vm.txIdx,
			vm.inputAmount,
		)
	}

	return calcWitnessSignatureHashRaw(
		subScript, sigHashes, hashType, &vm.tx, vm.txIdx, vm.inputAmount,
	)
}

// legacySigHash computes the digest a bare or P2SH signature checked by the
// engine commits to: the unified message when the signature opted in and
// ScriptVerifyUnifiedSigHash is set, the legacy one otherwise. The unified
// message needs every spent output; a script that opts in on an engine
// without a PrevOutputFetcher cannot be validated and fails.
func (vm *Engine) legacySigHash(subScript []byte,
	hashType SigHashType) ([]byte, error) {

	if hashType&SigHashUnified != 0 &&
		vm.hasFlag(ScriptVerifyUnifiedSigHash) {

		return CalcUnifiedSignatureHash(
			&vm.tx, vm.txIdx, UnifiedScriptBare, hashType,
			vm.prevOutFetcher, WithUnifiedScriptCode(subScript),
		)
	}

	return calcSignatureHash(subScript, hashType, &vm.tx, vm.txIdx), nil
}

// taprootSigHash computes the digest a taproot or tapscript signature
// checked by a verifier commits to, honouring the opt-in bit only when the
// verifier was built with ScriptVerifyUnifiedSigHash; without it BIP341's
// rules apply, which refuse the byte.
func taprootSigHash(unified bool, sigHashes *TxSigHashes, hType SigHashType,
	tx *wire.MsgTx, idx int, prevOutFetcher PrevOutputFetcher,
	sigHashOpts ...TaprootSigHashOption) ([]byte, error) {

	if !unified {
		return calcTaprootSignatureHashBIP341(
			sigHashes, hType, tx, idx, prevOutFetcher, sigHashOpts...,
		)
	}

	return calcTaprootSignatureHashRaw(
		sigHashes, hType, tx, idx, prevOutFetcher, sigHashOpts...,
	)
}
