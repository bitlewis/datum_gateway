/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of the DATUM Gateway project.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "datum_blocktemplates.h"

// Build a coinbase transaction hex from a list of (value, scriptPubKey) pairs.
// Segwit-serialised with a single input, which is what a template server sends.
static void cb_hex(char *out, size_t outsz, int nout, const uint64_t *vals, const char **spks) {
	char *p = out;
	size_t left = outsz;
	int n = snprintf(p, left, "02000000" "0001" "01"
	                 "0000000000000000000000000000000000000000000000000000000000000000" "ffffffff"
	                 "03" "510101" "ffffffff");
	p += n; left -= n;
	n = snprintf(p, left, "%02x", nout); p += n; left -= n;
	for (int i = 0; i < nout; i++) {
		uint64_t v = vals[i];
		for (int b = 0; b < 8; b++) { n = snprintf(p, left, "%02x", (unsigned)((v >> (8*b)) & 0xff)); p += n; left -= n; }
		n = snprintf(p, left, "%02x%s", (unsigned)(strlen(spks[i])/2), spks[i]); p += n; left -= n;
	}
	snprintf(p, left, "00000000");
}

// A pay-to-witness-pubkey-hash output: the payout the enforcer wrote for itself.
#define SPK_PAY "0014" "0102030405060708090a0b0c0d0e0f1011121314"
// OP_RETURN, 36-byte push, aa21a9ed, then the witness root.
#define SPK_WITNESS "6a24aa21a9ed" "1111111111111111111111111111111111111111111111111111111111111111"
// M2 ack sidechain: OP_RETURN, 37-byte push, d6e1c5df, slot, 32-byte hash.
#define SPK_M2 "6a25d6e1c5df01" "abababababababababababababababababababababababababababababababab"
// M4 ack bundles: OP_RETURN, 5-byte push, d77d1776, version.
#define SPK_M4 "6a05d77d177600"
// The sidechain block hash an M7 commits to, and the M8 request that bid for it.
#define BMM_HASH "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00"
#define SPK_M7 "6a25d161736802" BMM_HASH

static void take_the_value_and_the_commitments(void) {
	T_DATUM_TEMPLATE_DATA t = { 0 };
	char hex[2048];
	const uint64_t vals[] = { 312500000ULL, 0, 0, 0 };
	const char *spks[] = { SPK_PAY, SPK_WITNESS, SPK_M2, SPK_M4 };
	cb_hex(hex, sizeof(hex), 4, vals, spks);

	assert(datum_template_parse_coinbasetxn(&t, hex));
	// The value is the sum of every output, which is subsidy plus the fees of
	// the transaction set this coinbase came with.
	assert(t.coinbasevalue == 312500000ULL);
	assert(t.from_enforcer);
	// The payout is dropped -- that is ours to build -- and so is the witness
	// commitment, which we derive from the same transactions.
	assert(t.commitments_count == 2);
	assert(t.commitments[0].output_script_len == (int)strlen(SPK_M2)/2);
	assert(t.commitments[0].output_script[0] == 0x6a);
	assert(t.commitments[0].output_script[2] == 0xd6);
	assert(t.commitments[1].output_script[2] == 0xd7);
	printf("  value and commitments taken, payout and witness commitment dropped\n");
}

static void a_coinbase_paying_nothing_is_refused(void) {
	// Every output zero means we read the transaction wrong, or the server has
	// no idea what the block is worth. Mining it would forfeit the subsidy.
	T_DATUM_TEMPLATE_DATA t = { 0 };
	char hex[2048];
	const uint64_t vals[] = { 0 };
	const char *spks[] = { SPK_WITNESS };
	cb_hex(hex, sizeof(hex), 1, vals, spks);
	assert(!datum_template_parse_coinbasetxn(&t, hex));
	printf("  a coinbase paying nothing is refused\n");
}

static void a_truncated_coinbase_is_refused(void) {
	// Half-reading it would mean a plausible value and a missing commitment.
	T_DATUM_TEMPLATE_DATA t = { 0 };
	assert(!datum_template_parse_coinbasetxn(&t, "0200000000010001270000"));
	assert(!datum_template_parse_coinbasetxn(&t, "0200"));
	printf("  a truncated coinbase is refused\n");
}

static void too_many_commitments_is_refused_not_truncated(void) {
	T_DATUM_TEMPLATE_DATA t = { 0 };
	int n = DATUM_MAX_COMMITMENTS + 2;
	uint64_t *vals = calloc(n, sizeof(uint64_t));
	const char **spks = calloc(n, sizeof(char *));
	vals[0] = 312500000ULL; spks[0] = SPK_PAY;
	for (int i = 1; i < n; i++) { vals[i] = 0; spks[i] = SPK_M4; }
	char *hex = malloc(65536);
	cb_hex(hex, 65536, n, vals, spks);
	// Keeping the first N would be a vote that silently did not happen.
	assert(!datum_template_parse_coinbasetxn(&t, hex));
	free(hex); free(vals); free(spks);
	printf("  more commitments than we can carry is refused, not truncated\n");
}

// Build a fake template holding one M7 accept and the transactions given.
static void with_m7(T_DATUM_TEMPLATE_DATA *t, T_DATUM_TEMPLATE_TXN *txns, int ntx) {
	memset(t, 0, sizeof(*t));
	const char *m7 = SPK_M7;
	int len = (int)strlen(m7) / 2;
	for (int i = 0; i < len; i++) {
		unsigned v; sscanf(&m7[i*2], "%2x", &v);
		t->commitments[0].output_script[i] = (unsigned char)v;
	}
	t->commitments[0].output_script_len = len;
	t->commitments_count = 1;
	t->txns = txns;
	t->txn_count = ntx;
}

static void a_bmm_accept_needs_its_request_in_the_block(void) {
	// The 996403 fork in one assertion. An M7 accept commits to a sidechain
	// block that an M8 request bid for. Ship the accept without the request and
	// the node takes the block, builds on it, and reports nothing wrong, while
	// the enforcer rejects it -- so the pool mines a branch that cannot exist
	// and is told it is healthy the whole time.
	unsigned char m8[64] = { 0 };
	for (int i = 0; i < 32; i++) {
		unsigned v; sscanf(&BMM_HASH[i*2], "%2x", &v);
		m8[8 + i] = (unsigned char)v;   // the hash, somewhere inside the request
	}
	unsigned char unrelated[64] = { 0 };
	memset(unrelated, 0x5a, sizeof(unrelated));

	T_DATUM_TEMPLATE_TXN backed = { .txn_data_binary = m8, .size = sizeof(m8) };
	T_DATUM_TEMPLATE_DATA t;
	with_m7(&t, &backed, 1);
	assert(datum_template_bmm_accepts_are_backed(&t));

	T_DATUM_TEMPLATE_TXN orphaned = { .txn_data_binary = unrelated, .size = sizeof(unrelated) };
	with_m7(&t, &orphaned, 1);
	assert(!datum_template_bmm_accepts_are_backed(&t));

	// The shape truncation would produce: the accept survives in the coinbase
	// and the request is gone from the block.
	with_m7(&t, &backed, 0);
	assert(!datum_template_bmm_accepts_are_backed(&t));
	printf("  a BMM accept without its request in the block is refused\n");
}

// The rule the coinbaser now applies to commitments the pool sends.
//
// Those never pass through the template parser, so the guard that protects
// enforcer templates was silently not protecting them. It holds today only
// because the pool sends votes and never accepts -- an invariant nothing in
// the code enforced, and this is what enforces it.
static void a_pool_sent_accept_is_checked_against_our_own_block(void) {
	unsigned char m8[64] = { 0 };
	for (int i = 0; i < 32; i++) m8[16 + i] = (unsigned char)(0xA0 + i);
	unsigned char unrelated[64] = { 0 };
	memset(unrelated, 0x5a, sizeof(unrelated));

	unsigned char m7[256];
	const char *hex = SPK_M7;
	int len = (int)strlen(hex) / 2;
	for (int i = 0; i < len; i++) {
		unsigned v; sscanf(&hex[i*2], "%2x", &v);
		m7[i] = (unsigned char)v;
	}

	T_DATUM_TEMPLATE_TXN backed = { .txn_data_binary = m8, .size = sizeof(m8) };
	assert(datum_template_commitment_is_backed(m7, len, &backed, 1));

	// The case that matters: the pool's node had the request, ours does not.
	T_DATUM_TEMPLATE_TXN theirs = { .txn_data_binary = unrelated, .size = sizeof(unrelated) };
	assert(!datum_template_commitment_is_backed(m7, len, &theirs, 1));

	// And with no transactions at all, which is what an empty-block template
	// between two blocks looks like.
	assert(!datum_template_commitment_is_backed(m7, len, NULL, 0));

	// Votes commit to no transaction and must always pass, or applying this
	// rule to the pool's commitments would stop it voting through any gateway
	// that has no enforcer of its own.
	unsigned char m2[256];
	hex = SPK_M2;
	len = (int)strlen(hex) / 2;
	for (int i = 0; i < len; i++) {
		unsigned v; sscanf(&hex[i*2], "%2x", &v);
		m2[i] = (unsigned char)v;
	}
	assert(datum_template_commitment_is_backed(m2, len, NULL, 0));

	printf("  a pool-sent BMM accept is checked against our own transactions\n");
}

static void commitments_without_bmm_are_left_alone(void) {
	// M2 and M4 commit to no transaction, so the backing rule must not touch
	// them. A guard that failed here would stop the pool voting at all.
	T_DATUM_TEMPLATE_DATA t = { 0 };
	char hex[2048];
	const uint64_t vals[] = { 312500000ULL, 0, 0 };
	const char *spks[] = { SPK_PAY, SPK_M2, SPK_M4 };
	cb_hex(hex, sizeof(hex), 3, vals, spks);
	assert(datum_template_parse_coinbasetxn(&t, hex));
	assert(t.commitments_count == 2);
	t.txn_count = 0;
	assert(datum_template_bmm_accepts_are_backed(&t));
	printf("  sidechain and bundle votes need no transaction to back them\n");
}

static void a_real_enforcer_coinbase(void) {
	// Captured from the alphanet enforcer at height 996445: two outputs, the
	// pool's payout and a witness commitment, no votes pending. Pinning the
	// real bytes rather than only constructed ones -- the transaction is
	// segwit-serialised despite the coinbase having no witness to speak of,
	// and a hand-written fixture would have tidied that away.
	T_DATUM_TEMPLATE_DATA t = { 0 };
	static const char *real =
		"020000000001010000000000000000000000000000000000000000000000000000000000"
		"000000ffffffff04035d340fffffffff027b95c912000000001600141f8cf1fd34d0c377"
		"0c58023f1f0f7750b2dd18c30000000000000000266a24aa21a9ed52aeb9bd30449a1502"
		"50bd83cfc5aa41ac7526f50fff47ce76963b66cb02259b01200000000000000000000000"
		"00000000000000000000000000000000000000000000000000";
	assert(datum_template_parse_coinbasetxn(&t, real));
	assert(t.coinbasevalue == 315200891ULL);
	assert(t.commitments_count == 0);   // nothing to vote on that block
	assert(t.from_enforcer);
	printf("  a real enforcer coinbase parses to value %llu, no commitments\n",
	       (unsigned long long)t.coinbasevalue);
}

void datum_blocktemplates_tests(void) {
	printf("BIP300/301 template tests:\n");
	take_the_value_and_the_commitments();
	a_coinbase_paying_nothing_is_refused();
	a_truncated_coinbase_is_refused();
	too_many_commitments_is_refused_not_truncated();
	a_bmm_accept_needs_its_request_in_the_block();
	a_pool_sent_accept_is_checked_against_our_own_block();
	commitments_without_bmm_are_left_alone();
	a_real_enforcer_coinbase();
}
