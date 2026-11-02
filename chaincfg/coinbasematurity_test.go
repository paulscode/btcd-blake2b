// Copyright (c) 2026 The btcd developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import "testing"

// TestCoinbaseMaturityLongNotDeployed checks that a Params without the fields behaves
// exactly as it did before the rule existed. Every Params built outside this package, and
// three of the five in it, are in that state.
func TestCoinbaseMaturityLongNotDeployed(t *testing.T) {
	for _, params := range []*Params{
		&RegressionNetParams, &TestNet3Params, &SimNetParams,
	} {
		t.Run(params.Name, func(t *testing.T) {
			if params.CoinbaseMaturityLongDeployed() {
				t.Fatalf("rule reported as deployed")
			}
			if got := params.RelayCoinbaseMaturity(); got != 100 {
				t.Errorf("relay maturity = %d, want 100", got)
			}
			// Including at the heights mainnet uses, to catch a
			// zero value being read as "starts at height zero".
			for _, height := range []int32{0, 1, 973440, 979920} {
				if params.CoinbaseMaturityLongActiveAt(height) {
					t.Errorf("active at height %d", height)
				}
				got := params.RequiredCoinbaseMaturity(height, height)
				if got != 100 {
					t.Errorf("required maturity at %d = %d, want 100",
						height, got)
				}
			}
		})
	}
}

// TestRequiredCoinbaseMaturityMainNet walks the consensus rule across every edge of the
// deployment on the network it actually matters on.
func TestRequiredCoinbaseMaturityMainNet(t *testing.T) {
	const (
		start   = 973440
		release = 979920
		long    = 6480
	)

	tests := []struct {
		name           string
		coinbaseHeight int32
		spendHeight    int32
		want           int32
	}{{
		name:           "coinbase before the start height keeps the old rule",
		coinbaseHeight: start - 1,
		spendHeight:    start + 1,
		want:           100,
	}, {
		name:           "coinbase at the start height is covered",
		coinbaseHeight: start,
		spendHeight:    start + 1,
		want:           long,
	}, {
		name:           "spend one block before the release height still bites",
		coinbaseHeight: start,
		spendHeight:    release - 1,
		want:           long,
	}, {
		name:           "the rule stops applying at the release height",
		coinbaseHeight: start,
		spendHeight:    release,
		want:           100,
	}, {
		name:           "and stays stopped after it",
		coinbaseHeight: start + 1000,
		spendHeight:    release + 1,
		want:           100,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := MainNetParams.RequiredCoinbaseMaturity(
				test.coinbaseHeight, test.spendHeight,
			)
			if got != test.want {
				t.Errorf("got %d, want %d", got, test.want)
			}
		})
	}
}

// TestMainNetReleaseHeightIsASingleCliff checks the property the release height is there
// to produce: every coinbase caught by the rule becomes spendable at the same height,
// however deep or shallow it was when the rule started applying.
func TestMainNetReleaseHeightIsASingleCliff(t *testing.T) {
	const release = 979920

	for _, coinbaseHeight := range []int32{973440, 975000, 979000, 979819} {
		spendable := func(spendHeight int32) bool {
			required := MainNetParams.RequiredCoinbaseMaturity(
				coinbaseHeight, spendHeight,
			)
			return spendHeight-coinbaseHeight >= required
		}

		if spendable(release - 1) {
			t.Errorf("coinbase %d spendable at %d, before the release height",
				coinbaseHeight, release-1)
		}
		if !spendable(release) {
			t.Errorf("coinbase %d not spendable at the release height %d",
				coinbaseHeight, release)
		}
	}

	// A coinbase mined so late that a hundred blocks carries it past the
	// release height is held by the ordinary rule, not by this one.
	const late = 979850
	if MainNetParams.RequiredCoinbaseMaturity(late, late+99) != 100 {
		t.Errorf("late coinbase not on the ordinary rule")
	}
}

// TestTestNet4GraceWindow covers the one case where the start and enforce heights differ,
// which is the case a model built only from the start and release heights gets wrong: a
// coinbase mined inside the rule's reach but spent before enforcement begins is spendable
// on the ordinary hundred blocks.
func TestTestNet4GraceWindow(t *testing.T) {
	const (
		start   = 151406
		enforce = 151550
		release = 158111
	)

	if got := TestNet4Params.RequiredCoinbaseMaturity(start, enforce-1); got != 100 {
		t.Errorf("inside the grace window: got %d, want 100", got)
	}
	if got := TestNet4Params.RequiredCoinbaseMaturity(start, enforce); got != 6705 {
		t.Errorf("at the enforce height: got %d, want 6705", got)
	}
	if got := TestNet4Params.RequiredCoinbaseMaturity(start, release); got != 100 {
		t.Errorf("at the release height: got %d, want 100", got)
	}
}

// TestRelayCoinbaseMaturityIsNeverWeakerThanConsensus is the property that lets a wallet
// ask one question instead of three: a coin the relay depth clears cannot be refused by
// consensus either, whether the wallet knows the coinbase's height or not.
func TestRelayCoinbaseMaturityIsNeverWeakerThanConsensus(t *testing.T) {
	for _, params := range []*Params{&MainNetParams, &TestNet4Params} {
		t.Run(params.Name, func(t *testing.T) {
			deepest := params.RelayCoinbaseMaturity()

			heights := []int32{1}
			for _, edge := range []int32{
				params.CoinbaseMaturityLongStartHeight,
				params.CoinbaseMaturityLongEnforceHeight,
				params.CoinbaseMaturityLongReleaseHeight,
				params.CoinbaseMaturityRollingStartHeight,
			} {
				if edge > 1 {
					heights = append(heights, edge-1, edge, edge+500)
				}
			}
			for _, coinbaseHeight := range heights {
				relay := params.RelayCoinbaseMaturityAt(coinbaseHeight)
				if relay > deepest {
					t.Fatalf("coinbase %d: relay depth %d above the "+
						"deepest %d", coinbaseHeight, relay, deepest)
				}
				for _, offset := range []int32{
					0, 1, 100, relay - 1, relay, relay + 1,
					deepest - 1, deepest,
				} {
					spendHeight := coinbaseHeight + offset
					consensus := params.RequiredCoinbaseMaturity(
						coinbaseHeight, spendHeight,
					)
					if relay < consensus {
						t.Fatalf("coinbase %d spent at %d: relay depth %d "+
							"below consensus depth %d", coinbaseHeight,
							spendHeight, relay, consensus)
					}
				}
			}
		})
	}
}

// TestRelayCoinbaseMaturityDoesNotExpire records that the relay rule keeps applying after
// the release height, and to coinbases mined long before the start height. This is not a
// side effect of the deployment window; it is what the upgraded nodes do, and it is why a
// wallet cannot compute spendability from the heights alone.
func TestRelayCoinbaseMaturityDoesNotExpire(t *testing.T) {
	// Mined well before the fork, buried far deeper than the old rule asked,
	// consensus-valid, and still not relayable.
	const coinbaseHeight = 900000
	relay := MainNetParams.RelayCoinbaseMaturityAt(coinbaseHeight)
	if relay != 6480 {
		t.Fatalf("relay maturity = %d, want 6480", relay)
	}
	spendHeight := int32(coinbaseHeight + 200)
	if MainNetParams.RequiredCoinbaseMaturity(coinbaseHeight, spendHeight) != 100 {
		t.Errorf("consensus should not cover a pre-fork coinbase")
	}
	if spendHeight-coinbaseHeight >= relay {
		t.Errorf("relay should still hold a pre-fork coinbase at 200 deep")
	}
}

// TestRollingCoinbaseMaturityMainNet walks the rolling rule of Knots 29.4.3 across its
// edges: 25920 blocks for a coinbase from block 979919, enforced from that height with no
// release, while coinbases before it keep the long rule's answers.
func TestRollingCoinbaseMaturityMainNet(t *testing.T) {
	const (
		rollingStart = 979919
		rolling      = 25920
		longStart    = 973440
		release      = 979920
		long         = 6480
	)

	consensus := []struct {
		name                        string
		coinbaseHeight, spendHeight int32
		want                        int32
	}{
		{"the block before the start keeps the long rule", rollingStart - 1, rollingStart, long},
		{"which still ends at its release height", rollingStart - 1, release, 100},
		{"a coinbase at the start is covered", rollingStart, rollingStart + 1, rolling},
		{"and still is one block short", rollingStart, rollingStart + rolling - 1, rolling},
		{"and long after any release height", rollingStart + 5000, rollingStart + 100000, rolling},
		{"a long-rule coinbase spent at the rolling start", longStart, rollingStart, long},
		{"a pre-fork coinbase is untouched", 900000, rollingStart + 10, 100},
	}
	for _, test := range consensus {
		got := MainNetParams.RequiredCoinbaseMaturity(test.coinbaseHeight, test.spendHeight)
		if got != test.want {
			t.Errorf("consensus, %s: got %d, want %d", test.name, got, test.want)
		}
	}

	relay := []struct {
		coinbaseHeight int32
		want           int32
	}{
		{1, long}, {961640, long}, {longStart, long}, {rollingStart - 1, long},
		{rollingStart, rolling}, {rollingStart + 1, rolling}, {1100000, rolling},
	}
	for _, test := range relay {
		got := MainNetParams.RelayCoinbaseMaturityAt(test.coinbaseHeight)
		if got != test.want {
			t.Errorf("relay at %d: got %d, want %d", test.coinbaseHeight, got, test.want)
		}
	}
	if got := MainNetParams.RelayCoinbaseMaturity(); got != rolling {
		t.Errorf("deepest relay depth = %d, want %d", got, rolling)
	}

	// The cliff that matters to a miner: a coinbase from the rolling start
	// height becomes spendable, for relay and consensus, exactly 25920 deep.
	spendable := func(spendHeight int32) bool {
		return spendHeight-rollingStart >= MainNetParams.RelayCoinbaseMaturityAt(rollingStart) &&
			spendHeight-rollingStart >= MainNetParams.RequiredCoinbaseMaturity(rollingStart, spendHeight)
	}
	if spendable(rollingStart + rolling - 1) {
		t.Errorf("spendable one block early")
	}
	if !spendable(rollingStart + rolling) {
		t.Errorf("not spendable at %d deep", rolling)
	}
}

// TestRollingCoinbaseMaturityOnlyOnMainNet checks that the networks Knots 29.4.3 left
// alone are left alone here too.
func TestRollingCoinbaseMaturityOnlyOnMainNet(t *testing.T) {
	for _, params := range []*Params{
		&TestNet4Params, &RegressionNetParams, &TestNet3Params, &SimNetParams,
	} {
		if params.CoinbaseMaturityRollingDeployed() {
			t.Errorf("%s: rolling rule deployed", params.Name)
		}
	}
	if got := TestNet4Params.RelayCoinbaseMaturityAt(200000); got != 6705 {
		t.Errorf("testnet4 relay = %d, want 6705", got)
	}
	if got := RegressionNetParams.RelayCoinbaseMaturity(); got != 100 {
		t.Errorf("regtest relay = %d, want 100", got)
	}
}
