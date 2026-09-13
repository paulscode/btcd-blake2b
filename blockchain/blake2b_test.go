// Copyright (c) 2026 Paul Lamb
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

// TestCheckProofOfWorkRefusesHeaderV2 pins the rule that this package never
// checks a BLAKE2b (header v2) block id against a target: it refuses with
// ErrUnsupportedProofOfWork instead of silently treating the id as SHA256d
// work. A classic header still goes through the normal check.
func TestCheckProofOfWorkRefusesHeaderV2(t *testing.T) {
	// The first BLAKE2b mainnet block (961640), as serialized by Bitcoin
	// Knots v29.4.1 on 2026-09-12.
	const raw = "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc7684dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d0300000000000000000000001e0300000000000000000000000000000000000068ac0e000000000000000000000000000000000000000000000000000000000000000000"
	b, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	var v2 wire.BlockHeader
	if err := v2.Deserialize(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	if !v2.IsV2() {
		t.Fatal("fixture is not a v2 header")
	}

	err = checkProofOfWork(&v2, chaincfg.MainNetParams.PowLimit, BFNone)
	var rerr RuleError
	if !errors.As(err, &rerr) || rerr.ErrorCode != ErrUnsupportedProofOfWork {
		t.Fatalf("v2 header: got %v, want ErrUnsupportedProofOfWork", err)
	}

	// Even with the no-PoW flag the refusal stands: the flag skips the hash
	// comparison, not the question of which algorithm applies.
	err = checkProofOfWork(&v2, chaincfg.MainNetParams.PowLimit, BFNoPoWCheck)
	if !errors.As(err, &rerr) || rerr.ErrorCode != ErrUnsupportedProofOfWork {
		t.Fatalf("v2 header with BFNoPoWCheck: got %v, want ErrUnsupportedProofOfWork", err)
	}

	// The classic path is unchanged: mainnet genesis passes.
	genesis := chaincfg.MainNetParams.GenesisBlock.Header
	if err := checkProofOfWork(&genesis, chaincfg.MainNetParams.PowLimit, BFNone); err != nil {
		t.Fatalf("genesis header refused: %v", err)
	}
}
