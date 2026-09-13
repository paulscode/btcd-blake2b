// Copyright (c) 2026 Paul Lamb
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcjson_test

import (
	"encoding/json"
	"testing"

	"github.com/btcsuite/btcd/btcjson"
)

// TestGetBlockHeaderVerboseResultV2 decodes the verbose header Bitcoin Knots
// v29.4.1 returns for the first BLAKE2b block (mainnet 961640, captured
// 2026-09-12) and a classic header, checking that the v2 fields land and that
// their absence leaves the classic result untouched.
func TestGetBlockHeaderVerboseResultV2(t *testing.T) {
	const v2 = `{
  "hash": "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb",
  "confirmations": 10140,
  "height": 961640,
  "version": 536870912,
  "versionHex": "20000000",
  "merkleroot": "68c70bdcd063030abe9410d523d52a027c781176cc4960af3a6b0f5a51a837c1",
  "time": 1788070477,
  "mediantime": 1786526307,
  "nonce": 2356769110,
  "bits": "1a008d4f",
  "target": "000000000000008d4f0000000000000000000000000000000000000000000000",
  "difficulty": 30393776.10393918,
  "chainwork": "00000000000000000000000000000000000000013e002762b0a1ae991b033e89",
  "nTx": 798,
  "txcount": 798,
  "header_version": 2,
  "nonce2": "84daeb49",
  "nonce3": "4dca936a",
  "extranonce": "00000000b1ccf00d0300000000000000",
  "time_offset": 0,
  "header_flags": 0,
  "xor_key_mask_clear_bits": 0,
  "xor_key": "00000000000000000000000000000000",
  "mm_rhs": "0000000000000000000000000000000000000000000000000000000000000000",
  "previousblockhash": "00000000000000000001bbc439e13f749dca850d32c7a2834165338713027e65",
  "nextblockhash": "0000000000000010ef13157db08c138ea82aa1ac0ec360bdb9f101ce3ed7f7b6"
}`
	var r btcjson.GetBlockHeaderVerboseResult
	if err := json.Unmarshal([]byte(v2), &r); err != nil {
		t.Fatal(err)
	}
	if r.Version != 0x20000000 {
		t.Errorf("version %#x, want the v2 bit stripped (0x20000000)", r.Version)
	}
	if r.HeaderVersion == nil || *r.HeaderVersion != 2 {
		t.Errorf("header_version not decoded: %v", r.HeaderVersion)
	}
	if r.TxCount == nil || *r.TxCount != 798 {
		t.Errorf("txcount not decoded: %v", r.TxCount)
	}
	if r.Nonce2 != "84daeb49" || r.Nonce3 != "4dca936a" {
		t.Errorf("nonce2/nonce3 wrong: %q %q", r.Nonce2, r.Nonce3)
	}
	if r.Extranonce != "00000000b1ccf00d0300000000000000" {
		t.Errorf("extranonce wrong: %q", r.Extranonce)
	}
	if r.TimeOffset == nil || *r.TimeOffset != 0 || r.HeaderFlags == nil ||
		*r.HeaderFlags != 0 || r.XorKeyMaskClearBits == nil {
		t.Errorf("time_offset/header_flags/clear bits not decoded")
	}
	if len(r.XorKey) != 32 || len(r.MMRhs) != 64 {
		t.Errorf("xor_key/mm_rhs wrong lengths: %d %d", len(r.XorKey), len(r.MMRhs))
	}

	const v1 = `{
  "hash": "00000000000000000001bbc439e13f749dca850d32c7a2834165338713027e65",
  "confirmations": 10141,
  "height": 961639,
  "version": 537526288,
  "versionHex": "200a0010",
  "merkleroot": "dfc068187889b27995d7f705074d337c5f31885aff3d2184841f1c8fc952fe80",
  "time": 1787937269,
  "mediantime": 1786512548,
  "nonce": 3985050705,
  "bits": "1702353d",
  "difficulty": 1
}`
	var c btcjson.GetBlockHeaderVerboseResult
	if err := json.Unmarshal([]byte(v1), &c); err != nil {
		t.Fatal(err)
	}
	if c.HeaderVersion != nil || c.TxCount != nil || c.Nonce2 != "" ||
		c.XorKey != "" || c.MMRhs != "" {
		t.Errorf("classic header grew v2 fields: %+v", c)
	}

	// Re-encoding a classic result must not invent v2 keys.
	out, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"header_version", "txcount", "nonce2", "xor_key", "mm_rhs"} {
		if json.Valid(out) && containsKey(out, key) {
			t.Errorf("classic result marshals key %q", key)
		}
	}

	// The same fields exist on the getblock verbose result.
	var b btcjson.GetBlockVerboseResult
	if err := json.Unmarshal([]byte(v2), &b); err != nil {
		t.Fatal(err)
	}
	if b.HeaderVersion == nil || *b.HeaderVersion != 2 || b.TxCount == nil {
		t.Errorf("GetBlockVerboseResult did not decode v2 fields")
	}
}

func containsKey(doc []byte, key string) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(doc, &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}
