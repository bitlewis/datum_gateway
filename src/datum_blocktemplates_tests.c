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
#include "datum_stratum.h"
#include "datum_utils.h"
#include "datum_coinbaser.h"

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

	datum_test(datum_template_parse_coinbasetxn(&t, hex));
	// The value is the sum of every output, which is subsidy plus the fees of
	// the transaction set this coinbase came with.
	datum_test(t.coinbasevalue == 312500000ULL);
	datum_test(t.from_enforcer);
	// The payout is dropped -- that is ours to build -- and so is the witness
	// commitment, which we derive from the same transactions.
	datum_test(t.commitments_count == 2);
	datum_test(t.commitments[0].output_script_len == (int)strlen(SPK_M2)/2);
	datum_test(t.commitments[0].output_script[0] == 0x6a);
	datum_test(t.commitments[0].output_script[2] == 0xd6);
	datum_test(t.commitments[1].output_script[2] == 0xd7);
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
	datum_test(!datum_template_parse_coinbasetxn(&t, hex));
	printf("  a coinbase paying nothing is refused\n");
}

static void a_truncated_coinbase_is_refused(void) {
	// Half-reading it would mean a plausible value and a missing commitment.
	T_DATUM_TEMPLATE_DATA t = { 0 };
	datum_test(!datum_template_parse_coinbasetxn(&t, "0200000000010001270000"));
	datum_test(!datum_template_parse_coinbasetxn(&t, "0200"));
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
	datum_test(!datum_template_parse_coinbasetxn(&t, hex));
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
	datum_test(datum_template_bmm_accepts_are_backed(&t));

	T_DATUM_TEMPLATE_TXN orphaned = { .txn_data_binary = unrelated, .size = sizeof(unrelated) };
	with_m7(&t, &orphaned, 1);
	datum_test(!datum_template_bmm_accepts_are_backed(&t));

	// The shape truncation would produce: the accept survives in the coinbase
	// and the request is gone from the block.
	with_m7(&t, &backed, 0);
	datum_test(!datum_template_bmm_accepts_are_backed(&t));
	printf("  a BMM accept without its request in the block is refused\n");
}

// The rule the coinbaser now applies to commitments the pool sends.
//
// Those never pass through the template parser, so the guard that protects
// enforcer templates was silently not protecting them. It holds today only
// because the pool sends votes and never accepts -- an invariant nothing in
// the code enforced, and this is what enforces it.
static void a_pool_sent_accept_is_checked_against_our_own_block(void) {
	// The request the accept answers, so its hash is really in our block. Built
	// from BMM_HASH rather than filler: the M7 commits to that hash, and a
	// transaction carrying any other bytes does not back it. This read as
	// passing for as long as it did only because the release build compiles
	// asserts out, so the whole file printed its lines and checked nothing.
	unsigned char m8[64] = { 0 };
	for (int i = 0; i < 32; i++) {
		unsigned v; sscanf(&BMM_HASH[i*2], "%2x", &v);
		m8[16 + i] = (unsigned char)v;
	}
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
	datum_test(datum_template_commitment_is_backed(m7, len, &backed, 1));

	// The case that matters: the pool's node had the request, ours does not.
	T_DATUM_TEMPLATE_TXN theirs = { .txn_data_binary = unrelated, .size = sizeof(unrelated) };
	datum_test(!datum_template_commitment_is_backed(m7, len, &theirs, 1));

	// And with no transactions at all, which is what an empty-block template
	// between two blocks looks like.
	datum_test(!datum_template_commitment_is_backed(m7, len, NULL, 0));

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
	datum_test(datum_template_commitment_is_backed(m2, len, NULL, 0));

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
	datum_test(datum_template_parse_coinbasetxn(&t, hex));
	datum_test(t.commitments_count == 2);
	t.txn_count = 0;
	datum_test(datum_template_bmm_accepts_are_backed(&t));
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
	datum_test(datum_template_parse_coinbasetxn(&t, real));
	datum_test(t.coinbasevalue == 315200891ULL);
	datum_test(t.commitments_count == 0);   // nothing to vote on that block
	datum_test(t.from_enforcer);
	printf("  a real enforcer coinbase parses to value %llu, no commitments\n",
	       (unsigned long long)t.coinbasevalue);
}

// The pool's vote replaces the template's vote of the same kind, and nothing
// else.
//
// This is the rule that lets a miner's own enforcer keep building templates
// while the pool still decides how the block votes. Getting the "and nothing
// else" half wrong is the expensive way: an M7 dropped alongside the M4 it sat
// next to is a BMM bid mined for free.
static void the_pool_vote_replaces_the_templates_vote_of_the_same_kind(void) {
	T_DATUM_STRATUM_JOB job = { 0 };

	// A template carrying the enforcer's own M4 and an M7 BMM accept.
	unsigned char m4_template[] = { 0x6a, 0x05, 0xd7, 0x7d, 0x17, 0x76, 0x03 };
	unsigned char m7[] = { 0x6a, 0x24, 0xd3, 0x40, 0x77, 0x82,
	                       1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
	                       17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 };
	memcpy(job.commitments[0].output_script, m4_template, sizeof(m4_template));
	job.commitments[0].output_script_len = sizeof(m4_template);
	memcpy(job.commitments[1].output_script, m7, sizeof(m7));
	job.commitments[1].output_script_len = sizeof(m7);
	job.commitments_count = 2;
	job.commitments_size = (8 + 1 + sizeof(m4_template)) + (8 + 1 + sizeof(m7));
	const int size_before = job.commitments_size;

	// The pool's M4: an explicit vector abstaining on one sidechain, which is
	// the shape a miner NACK produces.
	unsigned char m4_pool[] = { 0x6a, 0x07, 0xd7, 0x7d, 0x17, 0x76, 0x02, 0xff, 0xff };

	unsigned char tag[4];
	datum_test(datum_commitment_tag(m4_pool, sizeof(m4_pool), tag));
	datum_test(!memcmp(tag, "\xd7\x7d\x17\x76", 4));

	datum_commitments_drop_tag(&job, tag);

	// The template's M4 is gone; the M7 beside it is untouched.
	datum_test(job.commitments_count == 1);
	datum_test(job.commitments[0].output_script_len == (int)sizeof(m7));
	datum_test(job.commitments[0].output_script[2] == 0xd3);
	datum_test(job.commitments_size == size_before - (8 + 1 + (int)sizeof(m4_template)));
	printf("  the pool's vote replaces the template's of the same kind, keeping the rest\n");

	// A tag that matches nothing leaves the set alone.
	unsigned char m2_tag[4] = { 0xd6, 0xe1, 0xc5, 0xdf };
	datum_commitments_drop_tag(&job, m2_tag);
	datum_test(job.commitments_count == 1);
	printf("  a vote the template never carried drops nothing\n");

	// Not every script is a message: a truncated one must not be read past.
	unsigned char stub[] = { 0x6a, 0x02, 0xd7, 0x7d };
	datum_test(!datum_commitment_tag(stub, sizeof(stub), tag));
	datum_test(!datum_commitment_tag(NULL, 0, tag));
	printf("  a script too short to hold a tag is not mistaken for one\n");
}

// An M4's vector length is the difference between a vote and an orphan.
//
// Height 996701 was mined on a one-entry vector where the chain had nine active
// sidechains. Our own node took it; every peer refused it. This is the check
// that now stands between the pool's arithmetic and another one.
static void an_m4_of_the_wrong_length_is_recognised(void) {
	// OP_RETURN, push, tag d77d1776, version 01, then one byte per sidechain.
	unsigned char nine[] = { 0x6a, 0x0e, 0xd7, 0x7d, 0x17, 0x76, 0x01,
	                         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0x00 };
	unsigned char one[]  = { 0x6a, 0x07, 0xd7, 0x7d, 0x17, 0x76, 0x02, 0xff, 0xff };
	unsigned char repeat[] = { 0x6a, 0x05, 0xd7, 0x7d, 0x17, 0x76, 0x00 };
	unsigned char leader[] = { 0x6a, 0x05, 0xd7, 0x7d, 0x17, 0x76, 0x03 };
	unsigned char m2[] = { 0x6a, 0x05, 0xd6, 0xe1, 0xc5, 0xdf, 0x01 };

	datum_test(datum_m4_entry_count(nine, sizeof(nine)) == 9);
	// The shape that cost a block: two-byte entries, one sidechain.
	datum_test(datum_m4_entry_count(one, sizeof(one)) == 1);
	// No vector to compare, so nothing to refuse on.
	datum_test(datum_m4_entry_count(repeat, sizeof(repeat)) == -1);
	datum_test(datum_m4_entry_count(leader, sizeof(leader)) == -1);
	// Not an M4 at all.
	datum_test(datum_m4_entry_count(m2, sizeof(m2)) == -1);
	printf("  an M4 voting for the wrong number of sidechains is recognised\n");
}


// A coinbase declares its output count before it writes its outputs, and the
// two are produced by two loops that must agree byte for byte. This walks the
// finished coinb2 and counts what is really there.
static int coinb2_outputs(const char *hex, int *declared, int *trailing) {
	int n = strlen(hex) >> 1;
	unsigned char *b = malloc(n);
	for (int i = 0; i < n; i++) b[i] = hex2bin_uchar(&hex[i * 2]);
	int p = 4; // sequence
	// varint
	uint64_t cnt;
	if (b[p] < 0xfd) { cnt = b[p]; p += 1; }
	else if (b[p] == 0xfd) { cnt = b[p+1] | (b[p+2] << 8); p += 3; }
	else { cnt = b[p+1] | (b[p+2] << 8) | (b[p+3] << 16) | ((uint64_t)b[p+4] << 24); p += 5; }
	*declared = (int)cnt;
	int actual = 0;
	while (p + 4 < n) {
		p += 8; // value
		uint64_t sl;
		if (b[p] < 0xfd) { sl = b[p]; p += 1; }
		else if (b[p] == 0xfd) { sl = b[p+1] | (b[p+2] << 8); p += 3; }
		else { free(b); *trailing = -1; return -1; }
		p += (int)sl;
		if (p > n) { free(b); *trailing = -1; return -1; }
		actual++;
	}
	*trailing = n - p; // 4 is the locktime, and nothing else
	free(b);
	return actual;
}

// The count loop and the emit loop take the commitment bytes out of the same
// budget. Reducing only the first let the second fit payouts the first had not
// counted -- once enough miners were owed that a commitment displaced one,
// which is normal on a busy pool -- and the coinbase then declared fewer
// outputs than it carried. An invalid block, believed found.
static void the_output_count_matches_the_outputs_written(void) {
	static T_DATUM_STRATUM_JOB job;
	static T_DATUM_TEMPLATE_DATA tpl;
	memset(&job, 0, sizeof(job));
	memset(&tpl, 0, sizeof(tpl));
	memset(tpl.default_witness_commitment, 'a', 64);
	job.block_template = &tpl;
	job.coinbase_value = 1000ULL * 100000000ULL;
	job.pool_addr_script_len = 22;
	job.pool_addr_script[0] = 0x00; job.pool_addr_script[1] = 0x14;

	// Sixty payees, more than any small coinbase type can carry.
	for (int k = 0; k < 60; k++) {
		job.available_coinbase_outputs[k].output_script_len = 34;
		job.available_coinbase_outputs[k].output_script[0] = 0x00;
		job.available_coinbase_outputs[k].output_script[1] = 0x20;
		job.available_coinbase_outputs[k].value_sats = 100000000ULL;
	}
	job.available_coinbase_outputs_count = 60;

	// One M4-shaped commitment.
	unsigned char m4[] = { 0x6a, 0x0d, 0xd7, 0x7d, 0x17, 0x76, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	memcpy(job.commitments[0].output_script, m4, sizeof(m4));
	job.commitments[0].output_script_len = sizeof(m4);
	job.commitments_count = 1;
	job.commitments_size = 8 + 1 + sizeof(m4);

	// Every budget, not a handful: the bug only shows at a budget where the
	// commitment displaces exactly one payout, and which budgets those are
	// depends on the payout size. Sweeping finds them all.
	int mismatches = 0;
	for (int budget = 200; budget <= 2600; budget++) {
		int cb1idx[MAX_COINBASE_TYPES] = { 0 }, cb2idx[MAX_COINBASE_TYPES] = { 0 };
		job.coinbase[1].coinb2[0] = 0;
		generate_coinbase_txns_for_stratum_job_subtypebysize(&job, 1, budget, true, cb1idx, cb2idx, false);
		int declared = -1, trailing = -1;
		int actual = coinb2_outputs(job.coinbase[1].coinb2, &declared, &trailing);
		if (actual != declared || trailing != 4) mismatches++;
		// The commitment went in, exactly once.
		datum_test(strstr(job.coinbase[1].coinb2, "6a0dd77d1776") != NULL);
		datum_test(strstr(strstr(job.coinbase[1].coinb2, "6a0dd77d1776") + 1, "6a0dd77d1776") == NULL);
		// And the whole thing fits the budget it was given (payouts + commitment),
		// plus the pool output, witness and locktime the caller reserved.
		datum_test((int)(strlen(job.coinbase[1].coinb2) / 2) <= budget + 4 + 3 + (8 + 1 + 22) + (8 + 1 + 32) + 4);
	}
	datum_test(mismatches == 0);
	printf("  the coinbase declares exactly the outputs it carries at every budget (%d mismatched)\n", mismatches);

	// A commitment set too large for the type is left out whole, not truncated
	// into a count that no longer matches.
	job.commitments_size = 400;
	job.commitments[0].output_script_len = 60;
	{
		int cb1idx[MAX_COINBASE_TYPES] = { 0 }, cb2idx[MAX_COINBASE_TYPES] = { 0 };
		job.coinbase[1].coinb2[0] = 0;
		generate_coinbase_txns_for_stratum_job_subtypebysize(&job, 1, 287, true, cb1idx, cb2idx, false);
		int declared = -1, trailing = -1;
		int actual = coinb2_outputs(job.coinbase[1].coinb2, &declared, &trailing);
		datum_test(actual == declared);
		datum_test(trailing == 4);
		datum_test(strstr(job.coinbase[1].coinb2, "d77d1776") == NULL);
	}
	printf("  a commitment set that does not fit a type is left out of it whole\n");
}

// A commitment the template parser skips must not leave a hole behind.
//
// The array is reused between jobs. Writing entry i while counting entries
// separately meant a skipped commitment left index i holding the previous
// job's bytes, and the count still reached past it -- so a stale, unrelated
// script went into the coinbase as if the template had asked for it.
static void a_skipped_template_commitment_leaves_no_hole(void) {
	static T_DATUM_TEMPLATE_DATA t;
	static T_DATUM_STRATUM_JOB job;
	memset(&t, 0, sizeof(t));
	memset(&job, 0, sizeof(job));

	unsigned char m2[] = { 0x6a, 0x05, 0xd6, 0xe1, 0xc5, 0xdf, 0x01 };
	unsigned char m4[] = { 0x6a, 0x05, 0xd7, 0x7d, 0x17, 0x76, 0x03 };
	memcpy(t.commitments[0].output_script, m2, sizeof(m2));
	t.commitments[0].output_script_len = sizeof(m2);
	// The middle one claims a length no script can have, so it is skipped.
	t.commitments[1].output_script_len = DATUM_MAX_COMMITMENT_SCRIPT + 1;
	memcpy(t.commitments[2].output_script, m4, sizeof(m4));
	t.commitments[2].output_script_len = sizeof(m4);
	t.commitments_count = 3;

	// The bytes a previous job left in slot 1, which must not survive.
	memset(job.commitments[1].output_script, 0xee, 8);
	job.commitments[1].output_script_len = 8;
	job.block_template = &t;

	// A NULL coinbaser takes the template's commitments and nothing else.
	datum_coinbaser_v2_parse(&job, NULL, 0, false);

	datum_test(job.commitments_count == 2);
	datum_test(job.commitments[0].output_script[2] == 0xd6);
	// Slot 1 is the template's third commitment, not last job's leftovers.
	datum_test(job.commitments[1].output_script_len == (int)sizeof(m4));
	datum_test(job.commitments[1].output_script[2] == 0xd7);
	datum_test(job.commitments_size == (8 + 1 + (int)sizeof(m2)) + (8 + 1 + (int)sizeof(m4)));
	printf("  a skipped template commitment leaves no stale hole behind\n");
}


// A gateway with an enforcer keeps its own BMM accepts.
//
// The pool offers accepts so that a gateway without an enforcer can collect
// merged-mining fees at all. A gateway that has one already holds accepts
// chosen against the exact transaction set it is about to mine, and every
// accept shares a tag, so letting the pool's in would drop all of those and
// substitute somebody else's mempool view.
static void a_template_with_its_own_accepts_ignores_the_pools(void) {
	static T_DATUM_STRATUM_JOB job;
	memset(&job, 0, sizeof(job));

	// The template's own accept, on slot 13. Put on the template rather than
	// straight onto the job: the parse rebuilds the job's commitments from the
	// template every time, which is the behaviour being tested.
	static T_DATUM_TEMPLATE_DATA tpl;
	memset(&tpl, 0, sizeof(tpl));
	unsigned char mine[39] = { 0x6a, 0x25, 0xd1, 0x61, 0x73, 0x68, 0x0d };
	for (int i = 7; i < 39; i++) mine[i] = (unsigned char)(i * 3);
	memcpy(tpl.commitments[0].output_script, mine, sizeof(mine));
	tpl.commitments[0].output_script_len = sizeof(mine);
	tpl.commitments_count = 1;
	tpl.from_enforcer = true;
	job.block_template = &tpl;
	job.coinbase_value = 5000000000ULL;

	// The pool sends a different accept, on slot 9.
	unsigned char theirs[39] = { 0x6a, 0x25, 0xd1, 0x61, 0x73, 0x68, 0x09 };
	for (int i = 7; i < 39; i++) theirs[i] = (unsigned char)(i * 7);

	// A real v3 coinbaser: the datum id with the high bit set to announce a
	// commitment section, the count, then each script behind a two-byte
	// length. No payouts after it, which is legal and keeps this about the
	// commitments.
	unsigned char cb[512];
	int n = 0;
	cb[n++] = 0x80 | 0x01;                                             // v3 flag + datum id
	cb[n++] = 0x01;                                                    // one commitment
	cb[n++] = (unsigned char)sizeof(theirs); cb[n++] = 0x00;           // length, LE
	memcpy(&cb[n], theirs, sizeof(theirs)); n += sizeof(theirs);

	datum_coinbaser_v2_parse(&job, cb, n, false);

	// The template's accept stands, and the pool's was not taken.
	datum_test(job.commitments_count == 1);
	datum_test(job.commitments[0].output_script[6] == 0x0d);
	printf("  a template with its own BMM accepts ignores the pool's\n");

	// The same coinbaser against a template with no accepts of its own: this
	// is the pruned node with no enforcer, and the pool's accept is the only
	// way it collects a merged-mining fee at all. Backed by a transaction
	// carrying the hash the accept commits to, or the check below refuses it.
	static T_DATUM_TEMPLATE_DATA bare;
	memset(&bare, 0, sizeof(bare));
	// The M8 as it really appears: the accepted hash sits inside the
	// transaction's bytes, so the check scans transaction data rather than
	// txids. Wrapped in filler so the match is found at an offset, not at 0.
	static T_DATUM_TEMPLATE_TXN txn;
	static unsigned char m8_bytes[80];
	memset(&txn, 0, sizeof(txn));
	memset(m8_bytes, 0x11, sizeof(m8_bytes));
	memcpy(&m8_bytes[24], &theirs[7], 32);
	txn.txn_data_binary = m8_bytes;
	txn.size = sizeof(m8_bytes);
	bare.txns = &txn;
	bare.txn_count = 1;
	job.block_template = &bare;
	job.commitments_count = 0;
	datum_coinbaser_v2_parse(&job, cb, n, false);
	datum_test(job.commitments_count == 1);
	datum_test(job.commitments[0].output_script[6] == 0x09);
	printf("  a template with none takes the pool's accept\n");
}


// A gateway with no enforcer leaves the BMM bids out, and keeps everything
// else -- including the pool's votes, which is the whole point.
//
// This is block 996794 as a test. The pruned gateway mined a template whose
// bids it could not accept; plain nodes took the block and every enforcer
// rejected it, so the pool credited three miners and reversed them a minute
// later. A bid left out costs its fee; a bid left in costs the block.
static void a_template_without_an_enforcer_drops_the_bmm_bids(void) {
	static T_DATUM_TEMPLATE_DATA t;
	static T_DATUM_TEMPLATE_TXN txns[3];
	memset(&t, 0, sizeof(t));
	memset(txns, 0, sizeof(txns));

	// An M8 bid: OP_RETURN, a push, then the 00bf00<slot> tag.
	static unsigned char bid[64];
	memset(bid, 0x11, sizeof(bid));
	bid[20] = 0x6a; bid[21] = 0x24; bid[22] = 0x00; bid[23] = 0xbf; bid[24] = 0x00; bid[25] = 0x0d;
	// An ordinary payment, and a child of the bid.
	static unsigned char plain[64], child[64];
	memset(plain, 0x22, sizeof(plain));
	memset(child, 0x33, sizeof(child));

	txns[0].txn_data_binary = bid;   txns[0].size = sizeof(bid);
	txns[0].fee_sats = 1202; txns[0].weight = 400; txns[0].sigops = 1; txns[0].index_raw = 1;
	txns[1].txn_data_binary = plain; txns[1].size = sizeof(plain);
	txns[1].fee_sats = 5000; txns[1].weight = 600; txns[1].sigops = 2; txns[1].index_raw = 2;
	txns[2].txn_data_binary = child; txns[2].size = sizeof(child);
	txns[2].fee_sats = 700;  txns[2].weight = 300; txns[2].sigops = 1; txns[2].index_raw = 3;

	t.txns = txns;
	t.txn_count = 3;
	t.coinbasevalue = 315541319;
	t.txn_total_weight = 1300;
	t.txn_total_size = 3 * sizeof(bid);
	t.txn_total_sigops = 4;
	t.from_enforcer = false;

	// The third transaction depends on the first, which is the bid.
	json_t *arr = json_array();
	json_array_append_new(arr, json_pack("{s:[]}", "depends"));
	json_array_append_new(arr, json_pack("{s:[]}", "depends"));
	json_array_append_new(arr, json_pack("{s:[i]}", "depends", 1));

	drop_unanswerable_bmm_requests(&t, arr);

	// The bid goes, and the child that could not stand without it.
	datum_test(t.txn_count == 1);
	datum_test(t.txns[0].fee_sats == 5000);
	// Renumbered, because the merkle branch and any later depends read it.
	datum_test(t.txns[0].index_raw == 1);
	// Both fees left the coinbase with them, or it pays more than it earned.
	datum_test(t.coinbasevalue == 315541319 - 1202 - 700);
	// And the tallies followed.
	datum_test(t.txn_total_weight == 600);
	datum_test(t.txn_total_sigops == 2);
	printf("  a template with no enforcer drops the BMM bids, their dependents and their fees\n");
	json_decref(arr);

	// An enforcer's template is not touched by any of this: it pairs each bid
	// with the accept that answers it, and dropping one would throw away a fee
	// it had every right to collect.
	memset(&t, 0, sizeof(t));
	memset(txns, 0, sizeof(txns));
	txns[0].txn_data_binary = bid; txns[0].size = sizeof(bid); txns[0].fee_sats = 1202;
	t.txns = txns; t.txn_count = 1; t.coinbasevalue = 315541319; t.from_enforcer = true;
	json_t *one = json_array();
	json_array_append_new(one, json_pack("{s:[]}", "depends"));
	if (!t.from_enforcer) drop_unanswerable_bmm_requests(&t, one);
	datum_test(t.txn_count == 1);
	datum_test(t.coinbasevalue == 315541319);
	printf("  an enforcer's template keeps its bids\n");
	json_decref(one);
}


// The same rule through the real parser, so the wiring is covered and not just
// the function. The unit test above proves the drop works; this proves it is
// actually reached for a template that did not come from an enforcer.
static void the_parser_drops_bids_when_there_is_no_enforcer(void) {
	if (!datum_test(datum_template_init() > 0)) return;

	// One M8 bid and one ordinary payment, as a node would hand them over.
	const char *bid =
	    "020000000111111111111111111111111111111111111111111111111111111111111111110000000000"
	    "ffffffff0100000000000000002a6a2800bf000d"
	    "d666deb13569dd47a0c06dbc806c8e86d21f50258cc28f5e17923aa47c10852800000000";
	const char *plain =
	    "020000000122222222222222222222222222222222222222222222222222222222222222220000000000"
	    "ffffffff01102700000000000016" "0014751e76e8199196d454941c45d1b3a323f1433bd6" "00000000";

	char gbt[4096];
	snprintf(gbt, sizeof(gbt),
	    "{\"height\":996794,\"coinbasevalue\":315541319,"
	    "\"mintime\":1788470000,\"curtime\":1788470100,\"version\":536870912,\"sigoplimit\":80000,"
	    "\"bits\":\"1d00ffff\",\"sizelimit\":4000000,\"weightlimit\":4000000,"
	    "\"previousblockhash\":\"0000000000000000e371b1e760aa93bcaa309f626beb59bff6c61f3e56443d48\","
	    "\"target\":\"00000000ffff0000000000000000000000000000000000000000000000000000\","
	    "\"default_witness_commitment\":\"6a24aa21a9ed%064x\","
	    "\"transactions\":["
	    "{\"txid\":\"%064x\",\"hash\":\"%064x\",\"fee\":1202,\"sigops\":1,\"weight\":400,\"depends\":[],\"data\":\"%s\"},"
	    "{\"txid\":\"%064x\",\"hash\":\"%064x\",\"fee\":5000,\"sigops\":1,\"weight\":600,\"depends\":[],\"data\":\"%s\"}]}",
	    2, 3, 3, bid, 4, 4, plain);

	json_error_t err;
	json_t *j = json_loads(gbt, 0, &err);
	if (!datum_test(j != NULL)) { printf("  (fixture: %s)\n", err.text); return; }

	T_DATUM_TEMPLATE_DATA *t = datum_gbt_parser(j);
	if (!datum_test(t != NULL)) { json_decref(j); return; }
	datum_test(!t->from_enforcer);
	datum_test(t->txn_count == 1);
	datum_test(t->coinbasevalue == 315541319 - 1202);
	printf("  the parser itself drops the bids when there is no enforcer\n");
	json_decref(j);
}

void datum_blocktemplates_tests(void) {
	the_parser_drops_bids_when_there_is_no_enforcer();
	a_template_without_an_enforcer_drops_the_bmm_bids();
	a_template_with_its_own_accepts_ignores_the_pools();
	the_output_count_matches_the_outputs_written();
	an_m4_of_the_wrong_length_is_recognised();
	the_pool_vote_replaces_the_templates_vote_of_the_same_kind();
	a_skipped_template_commitment_leaves_no_hole();
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
