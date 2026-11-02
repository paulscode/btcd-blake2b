// Copyright (c) 2026 The btcd developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

// The temporary coinbase maturity rules, as deployed by Bitcoin Knots for the BLAKE2b
// chain. Knots 29.4.2 raised the hundred block wait on newly mined coins to roughly forty
// five days (the long rule); Knots 29.4.3 kept that for the coinbases it covered and holds
// every coinbase from block 979919 on for 180 days (the rolling rule), until RDTS expires.
//
// The rules have two faces and they do not agree, which is the whole reason this file
// exists rather than a single larger constant:
//
//   - Consensus rejects a spend only while a rule is active. The long rule bites only for a
//     transaction included between its enforce height and its release height, and only for
//     a coinbase mined at or after its start height. The rolling rule bites on every spend
//     from its start height on, for a coinbase mined at or after that height. Where both
//     apply the deeper one wins, as Knots checks both. Everything else keeps the hundred
//     block rule. RequiredCoinbaseMaturity answers this.
//
//   - Relay is blunter. An upgraded node requires CoinbaseMaturityLong depth of every
//     coinbase mined before the rolling rule's start height, whatever height it was mined
//     at and whatever the heights say, and it keeps doing so after the release height; a
//     coinbase from the rolling start height on needs CoinbaseMaturityRolling.
//     RelayCoinbaseMaturityAt answers this for a coinbase whose height is known, and
//     RelayCoinbaseMaturity gives the deepest of them for one whose height is not.
//
// So a coinbase mined well before the fork, with two hundred confirmations, is a valid
// spend that no upgraded node will relay. Anything choosing coins to spend wants the relay
// answer; only block validation wants the consensus one.
//
// Not modeled: Knots returns a coinbase whose block's parent has a median time past at or
// after the RDTS expiry (2027-09-01 00:00 UTC on mainnet) to a hundred blocks. Here such a
// coinbase stays on the rolling rule. For relay and wallets that only holds coins longer;
// for block validation it would refuse a block Knots accepts once such coinbases are a
// hundred blocks deep, so it must be modeled before then if this package validates blocks.

// CoinbaseMaturityLongDeployed reports whether the long coinbase maturity rule is
// configured for this network. A Params built without the fields, which is every Params
// written before the rule existed, reports false and behaves exactly as it did.
func (p *Params) CoinbaseMaturityLongDeployed() bool {
	return p.CoinbaseMaturityLong > 0 &&
		p.CoinbaseMaturityLongReleaseHeight > 0
}

// CoinbaseMaturityLongActiveAt reports whether consensus enforces the long rule against a
// transaction included at the given height.
func (p *Params) CoinbaseMaturityLongActiveAt(height int32) bool {
	if !p.CoinbaseMaturityLongDeployed() {
		return false
	}

	return height >= p.CoinbaseMaturityLongEnforceHeight &&
		height < p.CoinbaseMaturityLongReleaseHeight
}

// CoinbaseMaturityRollingDeployed reports whether the rolling coinbase maturity rule is
// configured for this network.
func (p *Params) CoinbaseMaturityRollingDeployed() bool {
	return p.CoinbaseMaturityRolling > 0 &&
		p.CoinbaseMaturityRollingStartHeight > 0
}

// RequiredCoinbaseMaturity returns the depth a coinbase mined at coinbaseHeight must have
// reached before a transaction included at spendHeight may spend it without breaking
// consensus.
func (p *Params) RequiredCoinbaseMaturity(coinbaseHeight, spendHeight int32) int32 {
	required := int32(p.CoinbaseMaturity)

	if p.CoinbaseMaturityLongActiveAt(spendHeight) &&
		coinbaseHeight >= p.CoinbaseMaturityLongStartHeight &&
		p.CoinbaseMaturityLong > required {

		required = p.CoinbaseMaturityLong
	}

	if p.CoinbaseMaturityRollingDeployed() &&
		spendHeight >= p.CoinbaseMaturityRollingStartHeight &&
		coinbaseHeight >= p.CoinbaseMaturityRollingStartHeight &&
		p.CoinbaseMaturityRolling > required {

		required = p.CoinbaseMaturityRolling
	}

	return required
}

// RelayCoinbaseMaturityAt returns the depth a coinbase output mined at coinbaseHeight
// must have reached before an upgraded node will accept a spend of it into its mempool
// (Knots' CoinbaseMaturityPolicy).
//
// This is the number a wallet wants. It is at least as strict as consensus at every
// height, so a coin it clears cannot be refused by either.
func (p *Params) RelayCoinbaseMaturityAt(coinbaseHeight int32) int32 {
	required := int32(p.CoinbaseMaturity)

	if p.CoinbaseMaturityRollingDeployed() &&
		coinbaseHeight >= p.CoinbaseMaturityRollingStartHeight {

		if p.CoinbaseMaturityRolling > required {
			required = p.CoinbaseMaturityRolling
		}
		return required
	}

	if p.CoinbaseMaturityLongDeployed() && p.CoinbaseMaturityLong > required {
		required = p.CoinbaseMaturityLong
	}

	return required
}

// RelayCoinbaseMaturity returns the deepest RelayCoinbaseMaturityAt answers for any
// coinbase, for a caller that does not know where the coinbase was mined (Knots'
// maxCoinbaseMaturity). It holds some coins longer than relay requires; a caller that knows
// the coinbase's height should ask RelayCoinbaseMaturityAt.
func (p *Params) RelayCoinbaseMaturity() int32 {
	required := int32(p.CoinbaseMaturity)
	if p.CoinbaseMaturityLongDeployed() && p.CoinbaseMaturityLong > required {
		required = p.CoinbaseMaturityLong
	}
	if p.CoinbaseMaturityRollingDeployed() &&
		p.CoinbaseMaturityRolling > required {

		required = p.CoinbaseMaturityRolling
	}

	return required
}
