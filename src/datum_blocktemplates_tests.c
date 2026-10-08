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
#include "datum_conf.h"
#include "datum_protocol.h"

// Build a coinbase transaction hex from a list of (value, scriptPubKey) pairs.
// Segwit-serialised with a single input, which is what a template server sends.
static void unhex_into(const char *hex, uint8_t *out, uint32_t *n);

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
		const unsigned sl = (unsigned)(strlen(spks[i])/2);
		if (sl < 0xfd) {
			n = snprintf(p, left, "%02x%s", sl, spks[i]);
		} else {
			n = snprintf(p, left, "fd%02x%02x%s", sl & 0xff, sl >> 8, spks[i]);
		}
		p += n; left -= n;
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

static void too_many_commitments_leaves_the_rest_out(void) {
	// Refusing the template left every miner on stale work for as long as the
	// node kept putting the message in. What does not fit is left out; if that
	// is a BMM accept, the job is marked, and is served empty work.
	T_DATUM_TEMPLATE_DATA t = { 0 };
	int n = DATUM_MAX_COMMITMENTS + 2;
	uint64_t *vals = calloc(n, sizeof(uint64_t));
	const char **spks = calloc(n, sizeof(char *));
	vals[0] = 312500000ULL; spks[0] = SPK_PAY;
	for (int i = 1; i < n; i++) { vals[i] = 0; spks[i] = SPK_M4; }
	char *hex = malloc(200000);
	cb_hex(hex, 200000, n, vals, spks);
	datum_test(datum_template_parse_coinbasetxn(&t, hex));
	datum_test(t.commitments_count == DATUM_MAX_COMMITMENTS);
	datum_test(!t.bmm_accepts_dropped);
	spks[n - 1] = SPK_M7;
	cb_hex(hex, 200000, n, vals, spks);
	datum_test(datum_template_parse_coinbasetxn(&t, hex));
	datum_test(t.bmm_accepts_dropped);
	free(hex); free(vals); free(spks);
	printf("  what does not fit is left out, and a left out accept makes the job empty work\n");
}

static void a_proposal_fits(void) {
	// A sidechain proposal (M1) with the longest title and description.
	T_DATUM_TEMPLATE_DATA t = { 0 };
	static char m1[2 * 1360 + 1];
	int k = 0;
	// OP_RETURN OP_PUSHDATA2 <len LE>, then the tag, the slot and the description.
	const int body = 4 + 1 + 1 + 1 + 255 + 1024 + 32 + 32;
	k += sprintf(&m1[k], "6a4d%02x%02x" "d5e0c4af" "02" "00" "ff", body & 0xff, body >> 8);
	for (int i = 0; i < 255 + 1024 + 64; i++) k += sprintf(&m1[k], "41");
	uint64_t vals[2] = { 312500000ULL, 0 };
	const char *spks[2] = { SPK_PAY, m1 };
	char *hex = malloc(8192);
	cb_hex(hex, 8192, 2, vals, spks);
	datum_test(datum_template_parse_coinbasetxn(&t, hex));
	datum_test(t.commitments_count == 1);
	free(hex);
	printf("  the longest sidechain proposal is carried\n");
}

static void only_what_chains_reads_as_a_bid_is_one(void) {
	// A transaction anyone can send, with an output that looks like a bid but is
	// not one to Chains, which therefore puts no accept in the block: taking it
	// for a bid made every job empty work, for free.
	uint8_t b[512];
	uint32_t n;
	char hex[1024];
	char body[2 * 65 + 1];
	for (int i = 0; i < 65; i++) sprintf(&body[2 * i], "%02x", i);
	// One input, two outputs: a payment, then 6a44 00bf00 ... as output 1.
	snprintf(hex, sizeof(hex), "02000000" "01" "%064x" "00000000" "00" "ffffffff" "02"
	         "1027000000000000" "16" "0014" "0102030405060708090a0b0c0d0e0f1011121314"
	         "0000000000000000" "46" "6a44" "00bf00" "%s" "00000000", 0, body);
	unhex_into(hex, b, &n);
	datum_test(!txn_has_bmm_request_output(b, n));
	// The shape as output 0, but a short push.
	snprintf(hex, sizeof(hex), "02000000" "01" "%064x" "00000000" "00" "ffffffff" "01"
	         "0000000000000000" "07" "6a05" "00bf000000" "00000000", 0);
	unhex_into(hex, b, &n);
	datum_test(!txn_has_bmm_request_output(b, n));
	// The real thing.
	snprintf(hex, sizeof(hex), "02000000" "01" "%064x" "00000000" "00" "ffffffff" "01"
	         "0000000000000000" "46" "6a44" "00bf00" "%s" "00000000", 0, body);
	unhex_into(hex, b, &n);
	datum_test(txn_has_bmm_request_output(b, n));
	printf("  only output 0 with the exact shape is a bid\n");
}

static void a_pool_vote_has_to_fit_the_template(void) {
	T_DATUM_TEMPLATE_DATA t = { 0 };
	const unsigned char one_byte[] = { 0x6a, 0x07, 0xd7, 0x7d, 0x17, 0x76, 0x01, 0x00, 0xff };
	const unsigned char follow[] = { 0x6a, 0x05, 0xd7, 0x7d, 0x17, 0x76, 0x03 };
	// A node that does not say (an enforcer) leaves it to the check against the
	// template's own vote: the pool's votes still go through, as on eCash.
	datum_test(datum_m4_fits_template(one_byte, sizeof(one_byte), &t));
	t.votable_known = true;
	t.votable_count = 2;
	t.votable_bundles[0] = 1;
	t.votable_bundles[1] = 0;
	datum_test(datum_m4_fits_template(one_byte, sizeof(one_byte), &t));
	datum_test(datum_m4_fits_template(follow, sizeof(follow), &t));
	// A bundle index past the bundles pending.
	t.votable_bundles[0] = 0;
	datum_test(!datum_m4_fits_template(one_byte, sizeof(one_byte), &t));
	// A sidechain more or less.
	t.votable_bundles[0] = 1;
	t.votable_count = 3;
	datum_test(!datum_m4_fits_template(one_byte, sizeof(one_byte), &t));
	// Two bytes where one would do.
	t.votable_count = 2;
	const unsigned char two_bytes[] = { 0x6a, 0x09, 0xd7, 0x7d, 0x17, 0x76, 0x02, 0x00, 0x00, 0xff, 0xff };
	datum_test(!datum_m4_fits_template(two_bytes, sizeof(two_bytes), &t));
	printf("  a vote the pool sends has to fit the template's sidechains and bundles\n");
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

	// A commitment too large for the type is left out, not truncated into a
	// count that no longer matches.
	job.commitments[0].output_script_len = 300;
	job.commitments_size = 8 + 3 + 300;
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
	printf("  a commitment that does not fit a type is left out of it\n");
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
static void pool_commitments_follow_chains_rules(void) {
	static T_DATUM_STRATUM_JOB job;
	memset(&job, 0, sizeof(job));
	static T_DATUM_TEMPLATE_DATA tpl;
	memset(&tpl, 0, sizeof(tpl));
	tpl.from_enforcer = true;
	job.block_template = &tpl;
	job.coinbase_value = 5000000000ULL;

	// Two acks for slot 3, an ack for slot 4, a script that is not one push, and an M4 twice.
	unsigned char ack3a[39] = { 0x6a, 0x25, 0xd6, 0xe1, 0xc5, 0xdf, 0x03 };
	unsigned char ack3b[39] = { 0x6a, 0x25, 0xd6, 0xe1, 0xc5, 0xdf, 0x03 };
	unsigned char ack4[39] = { 0x6a, 0x25, 0xd6, 0xe1, 0xc5, 0xdf, 0x04 };
	for (int i = 7; i < 39; i++) { ack3a[i] = (unsigned char)i; ack3b[i] = (unsigned char)(i + 1); ack4[i] = (unsigned char)(i + 2); }
	unsigned char sigops[8] = { 0x6a, 0x02, 0xd6, 0xe1, 0xac, 0xac, 0xac, 0xac };
	unsigned char m4[8] = { 0x6a, 0x06, 0xd7, 0x7d, 0x17, 0x76, 0x00, 0xff };
	unsigned char cb[1024];
	int n = 0;
	cb[n++] = 0x80 | 0x01;
	cb[n++] = 6;
	const unsigned char *scripts[6] = { ack3a, ack3b, ack4, sigops, m4, m4 };
	const int lens[6] = { 39, 39, 39, 8, 8, 8 };
	for (int i = 0; i < 6; i++) {
		cb[n++] = (unsigned char)lens[i]; cb[n++] = 0;
		memcpy(&cb[n], scripts[i], lens[i]); n += lens[i];
	}
	datum_coinbaser_v2_parse(&job, cb, n, false);
	// One ack per slot, no script with sigops, one M4.
	int acks3 = 0, acks4 = 0, m4s = 0;
	for (int c = 0; c < job.commitments_count; c++) {
		const unsigned char *o = job.commitments[c].output_script;
		datum_test(datum_script_is_one_push(o, job.commitments[c].output_script_len));
		if (o[2] == 0xd6 && o[6] == 0x03) acks3++;
		if (o[2] == 0xd6 && o[6] == 0x04) acks4++;
		if (o[2] == 0xd7) m4s++;
	}
	datum_test(acks3 == 1 && acks4 == 1);
	datum_test(m4s <= 1);
	printf("  pool commitments follow Chains' rules: one per kind and slot, one M4, one push each\n");

	// The template's own ack for slot 3 is replaced by the pool's, not taken for a duplicate of it.
	memset(&job, 0, sizeof(job));
	memset(&tpl, 0, sizeof(tpl));
	unsigned char own3[39] = { 0x6a, 0x25, 0xd6, 0xe1, 0xc5, 0xdf, 0x03 };
	for (int i = 7; i < 39; i++) own3[i] = 0x77;
	memcpy(tpl.commitments[0].output_script, own3, sizeof(own3));
	tpl.commitments[0].output_script_len = sizeof(own3);
	tpl.commitments_count = 1;
	tpl.from_enforcer = true;
	job.block_template = &tpl;
	job.coinbase_value = 5000000000ULL;
	n = 0;
	cb[n++] = 0x80 | 0x01;
	cb[n++] = 1;
	cb[n++] = 39; cb[n++] = 0;
	memcpy(&cb[n], ack3a, 39); n += 39;
	datum_coinbaser_v2_parse(&job, cb, n, false);
	datum_test(job.commitments_count == 1);
	datum_test(job.commitments[0].output_script[7] == ack3a[7]);
	printf("  the pool's ack replaces the template's for the same sidechain\n");

	// The same slot twice in two encodings (a direct push and PUSHDATA1, both
	// of which Chains reads), the same proposal twice, and payouts that are
	// not addresses: one of each kind is carried, and only the address is paid.
	memset(&job, 0, sizeof(job));
	memset(&tpl, 0, sizeof(tpl));
	tpl.from_enforcer = true;
	job.block_template = &tpl;
	job.coinbase_value = 5000000000ULL;
	unsigned char ack3long[40] = { 0x6a, 0x4c, 0x25, 0xd6, 0xe1, 0xc5, 0xdf, 0x03 };
	for (int i = 8; i < 40; i++) ack3long[i] = 0x55;
	unsigned char m1[12] = { 0x6a, 0x0a, 0xd5, 0xe0, 0xc4, 0xaf, 0x07, 1, 2, 3, 4, 5 };
	n = 0;
	cb[n++] = 0x80 | 0x01;
	cb[n++] = 4;
	const unsigned char *scripts2[4] = { ack3a, ack3long, m1, m1 };
	const int lens2[4] = { 39, 40, 12, 12 };
	for (int i = 0; i < 4; i++) {
		cb[n++] = (unsigned char)lens2[i]; cb[n++] = 0;
		memcpy(&cb[n], scripts2[i], lens2[i]); n += lens2[i];
	}
	// Payouts: an OP_RETURN with an accept's tag, an escrow script
	// (OP_DRIVECHAIN 01 <slot> OP_TRUE), then a P2WPKH address.
	unsigned char opret[39] = { 0x6a, 0x25, 0xd1, 0x61, 0x73, 0x68, 0x09 };
	unsigned char escrow[4] = { 0xb4, 0x01, 0x03, 0x51 };
	unsigned char p2wpkh[22] = { 0x00, 0x14 };
	const unsigned char *payees[3] = { opret, escrow, p2wpkh };
	const int plens[3] = { 39, 4, 22 };
	for (int i = 0; i < 3; i++) {
		pk_u64le(cb, n, 1000000ULL); n += 8;
		cb[n++] = (unsigned char)plens[i];
		memcpy(&cb[n], payees[i], plens[i]); n += plens[i];
	}
	datum_coinbaser_v2_parse(&job, cb, n, false);
	int acks = 0, m1s = 0;
	for (int c = 0; c < job.commitments_count; c++) {
		unsigned char t[4];
		datum_test(datum_commitment_tag(job.commitments[c].output_script, job.commitments[c].output_script_len, t));
		if (t[0] == 0xd6) acks++;
		if (t[0] == 0xd5) m1s++;
	}
	datum_test(acks == 1 && m1s == 1);
	datum_test(job.available_coinbase_outputs_count == 1);
	datum_test(job.available_coinbase_outputs[0].output_script_len == 22);
	datum_test(datum_payout_script_is_standard(p2wpkh, 22) && !datum_payout_script_is_standard(escrow, 4) && !datum_payout_script_is_standard(opret, 39));
	printf("  one per slot whatever the push, no proposal twice, and pool payouts only to addresses\n");
}

static void a_malformed_pool_payload_leaves_the_template_whole(void) {
	static T_DATUM_STRATUM_JOB job;
	memset(&job, 0, sizeof(job));
	// The template acks a sidechain proposal (M2).
	static T_DATUM_TEMPLATE_DATA tpl;
	memset(&tpl, 0, sizeof(tpl));
	unsigned char ack[39] = { 0x6a, 0x25, 0xd6, 0xe1, 0xc5, 0xdf, 0x03 };
	for (int i = 7; i < 39; i++) ack[i] = (unsigned char)(i * 5);
	memcpy(tpl.commitments[0].output_script, ack, sizeof(ack));
	tpl.commitments[0].output_script_len = sizeof(ack);
	tpl.commitments_count = 1;
	tpl.from_enforcer = true;
	job.block_template = &tpl;
	job.coinbase_value = 5000000000ULL;

	// The pool sends an ack of its own, which replaces the template's acks, and
	// then a second commitment cut short: the whole payload is refused.
	unsigned char theirs[39] = { 0x6a, 0x25, 0xd6, 0xe1, 0xc5, 0xdf, 0x04 };
	for (int i = 7; i < 39; i++) theirs[i] = (unsigned char)(i * 11);
	unsigned char cb[512];
	int n = 0;
	cb[n++] = 0x80 | 0x01;
	cb[n++] = 0x02;                                                    // two commitments
	cb[n++] = (unsigned char)sizeof(theirs); cb[n++] = 0x00;
	memcpy(&cb[n], theirs, sizeof(theirs)); n += sizeof(theirs);
	cb[n++] = 50; cb[n++] = 0x00;                                      // 50 bytes promised...
	cb[n++] = 0x6a;                                                    // ...one given
	datum_coinbaser_v2_parse(&job, cb, n, false);

	// Not half of it: the template's own ack, whole, and no pool payouts.
	datum_test(job.available_coinbase_outputs_count == 0);
	datum_test(job.commitments_count == 1);
	datum_test(job.commitments[0].output_script[6] == 0x03);
	printf("  a malformed pool payload leaves the template's commitments whole\n");
}

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
	// A real one: version, one input, one output whose script is the M8 for slot 9 and the
	// sidechain block the accept names, then the lock time.
	static unsigned char m8_bytes[4 + 1 + 36 + 1 + 4 + 1 + 8 + 1 + 70 + 4];
	memset(&txn, 0, sizeof(txn));
	memset(m8_bytes, 0, sizeof(m8_bytes));
	int k = 0;
	m8_bytes[k++] = 0x02; k += 3;                         // version
	m8_bytes[k++] = 0x01; k += 36;                        // one input, its outpoint
	m8_bytes[k++] = 0x00;                                 // empty script
	memset(&m8_bytes[k], 0xff, 4); k += 4;                // sequence
	m8_bytes[k++] = 0x01; k += 8;                         // one output, value 0
	m8_bytes[k++] = 70;
	m8_bytes[k++] = 0x6a; m8_bytes[k++] = 0x44;
	m8_bytes[k++] = 0x00; m8_bytes[k++] = 0xbf; m8_bytes[k++] = 0x00;
	m8_bytes[k++] = 0x09;                                 // slot
	memcpy(&m8_bytes[k], &theirs[7], 32); k += 32;        // the sidechain block
	k += 32;                                              // the previous mainchain block
	k += 4;                                               // lock time
	txn.txn_data_binary = m8_bytes;
	txn.size = (uint32_t)k;
	bare.txns = &txn;
	bare.txn_count = 1;
	job.block_template = &bare;
	job.commitments_count = 0;
	datum_coinbaser_v2_parse(&job, cb, n, false);
	datum_test(job.commitments_count == 1);
	datum_test(job.commitments[0].output_script[6] == 0x09);
	printf("  a template with none takes the pool's accept\n");
}


// A pool acking two proposals gets two M2s into the block.
//
// Every M2 carries the same tag, and the merge cleared by tag once per
// incoming message: the second ack deleted the first, so a pool backing two
// sidechains showed two ACKs in its own interface and mined one. Both of
// epool's proposals -- RISCy on slot 3 and Snowside on slot 88 -- were
// standing ACK, and block 996,812 went out acking only Snowside.
//
// The M4 beside them still replaces the template's, because there really is
// only one M4 in a block. That is the difference the fix turns on: a tag is
// cleared once for the whole merge, not once per message carrying it.
static void the_pool_can_ack_more_than_one_proposal(void) {
	static T_DATUM_STRATUM_JOB job;
	static T_DATUM_TEMPLATE_DATA tpl;
	memset(&job, 0, sizeof(job));
	memset(&tpl, 0, sizeof(tpl));

	// The template brings an M4 of its own, which the pool's must replace.
	unsigned char m4_template[] = { 0x6a, 0x05, 0xd7, 0x7d, 0x17, 0x76, 0x00 };
	memcpy(tpl.commitments[0].output_script, m4_template, sizeof(m4_template));
	tpl.commitments[0].output_script_len = sizeof(m4_template);
	tpl.commitments_count = 1;
	job.block_template = &tpl;
	job.coinbase_value = 5000000000ULL;

	// Two acks that differ only in the proposal hash inside them, and the
	// pool's own M4.
	unsigned char m2_a[39] = { 0x6a, 0x25, 0xd6, 0xe1, 0xc5, 0xdf };
	unsigned char m2_b[39] = { 0x6a, 0x25, 0xd6, 0xe1, 0xc5, 0xdf };
	for (int i = 6; i < 39; i++) { m2_a[i] = (unsigned char)(i * 3); m2_b[i] = (unsigned char)(i * 5); }
	unsigned char m4_pool[] = { 0x6a, 0x05, 0xd7, 0x7d, 0x17, 0x76, 0x03 };

	unsigned char cb[512];
	int n = 0;
	cb[n++] = 0x80 | 0x01;
	cb[n++] = 0x03; // two acks and a vote
	cb[n++] = (unsigned char)sizeof(m2_a); cb[n++] = 0x00;
	memcpy(&cb[n], m2_a, sizeof(m2_a)); n += sizeof(m2_a);
	cb[n++] = (unsigned char)sizeof(m2_b); cb[n++] = 0x00;
	memcpy(&cb[n], m2_b, sizeof(m2_b)); n += sizeof(m2_b);
	cb[n++] = (unsigned char)sizeof(m4_pool); cb[n++] = 0x00;
	memcpy(&cb[n], m4_pool, sizeof(m4_pool)); n += sizeof(m4_pool);

	datum_coinbaser_v2_parse(&job, cb, n, false);

	int acks = 0, votes = 0;
	bool saw_a = false, saw_b = false;
	for (int i = 0; i < job.commitments_count; i++) {
		unsigned char tag[4];
		if (!datum_commitment_tag(job.commitments[i].output_script,
		                          job.commitments[i].output_script_len, tag)) continue;
		if (!memcmp(tag, "\xd6\xe1\xc5\xdf", 4)) {
			acks++;
			if (!memcmp(job.commitments[i].output_script, m2_a, sizeof(m2_a))) saw_a = true;
			if (!memcmp(job.commitments[i].output_script, m2_b, sizeof(m2_b))) saw_b = true;
		}
		if (!memcmp(tag, "\xd7\x7d\x17\x76", 4)) {
			votes++;
			// The pool's, not the template's: version 0x03, not 0x00.
			datum_test(job.commitments[i].output_script[6] == 0x03);
		}
	}
	if (!datum_test(acks == 2)) printf("    kept %d ack(s), want 2\n", acks);
	datum_test(saw_a && saw_b);
	// Exactly one M4, and the template's is the one that went.
	datum_test(votes == 1);
	printf("  two acked proposals both reach the coinbase, beside a single vote\n");
}


// Dropping a transaction changes what the coinbase has to say about the set.
//
// The node's default_witness_commitment describes the transactions the node
// offered. Take one out and keep its commitment and the block is rejected as
// bad-witness-merkle-match -- which is what 996,795 was: a block whose bids had
// been correctly dropped, whose merkle root was right, and whose coinbase still
// described the template it came from.
//
// The expected values here come from an independent implementation of the same
// rule, the one checked against a live node's own answer over 2,330
// transactions. Two implementations agreeing is the only evidence available
// without a node in the test.
static void dropping_a_bid_rewrites_the_witness_commitment(void) {
	static T_DATUM_TEMPLATE_DATA t;
	static T_DATUM_TEMPLATE_TXN txns[3];
	static unsigned char bid[64], plain[64], other[64];
	memset(bid, 0x11, sizeof(bid));
	bid[20] = 0x6a; bid[21] = 0x24; bid[22] = 0x00; bid[23] = 0xbf; bid[24] = 0x00; bid[25] = 0x0d;
	memset(plain, 0x22, sizeof(plain));
	memset(other, 0x33, sizeof(other));

	// The commitment the node handed us, describing all three.
	static const char *stale = "6a24aa21a9ed9ccbde7801c3e3e8e11da5764ffa18ea6b55b3da136c4ee890e352bff9087ef0";

	struct { int keep; const char *want; } cases[] = {
		// One transaction left: an even level, hashed straight to the root.
		{ 1, "6a24aa21a9eda997fefd9694e5b6fec7a500b38e64562b5698e1a4c51b0595371ff6f17ab214" },
		// Two left, so three leaves with the coinbase: an odd level, whose last
		// entry is duplicated to pair it.
		{ 2, "6a24aa21a9edc56f03bfdb3d4b720e1f5593ecc94b0bebedff8df1cdd812870bb450fcc0028a" },
	};

	for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
		memset(&t, 0, sizeof(t));
		memset(txns, 0, sizeof(txns));
		// The bid first, then as many ordinary transactions as this case keeps.
		txns[0].txn_data_binary = bid;   txns[0].size = sizeof(bid);   txns[0].fee_sats = 1202;
		txns[1].txn_data_binary = plain; txns[1].size = sizeof(plain); txns[1].fee_sats = 5000;
		txns[2].txn_data_binary = other; txns[2].size = sizeof(other); txns[2].fee_sats = 700;
		memset(txns[1].hash_bin, 0x22, 32);
		memset(txns[2].hash_bin, 0x33, 32);
		t.txns = txns;
		t.txn_count = 1 + cases[c].keep;
		t.coinbasevalue = 315541319;
		t.from_enforcer = false;
		strcpy(t.default_witness_commitment, stale);

		json_t *arr = json_array();
		for (uint32_t i = 0; i < t.txn_count; i++) {
			json_array_append_new(arr, json_pack("{s:[]}", "depends"));
		}
		datum_test(drop_unanswerable_bmm_requests(&t, arr));
		json_decref(arr);

		datum_test(t.txn_count == (uint32_t)cases[c].keep);
		if (!datum_test(!strcmp(t.default_witness_commitment, cases[c].want))) {
			printf("    got  %s\n    want %s\n", t.default_witness_commitment, cases[c].want);
		}
		// The binary form is what the parser derived from the hex, and the two
		// have to keep agreeing.
		datum_test(t.default_witness_commitment_bin[0] == 0x6a);
		datum_test(t.default_witness_commitment_bin[5] == 0xed);
	}
	printf("  dropping a bid rewrites the witness commitment over what is left\n");

	// Nothing dropped, nothing rewritten: the node's own commitment already
	// describes the block, and recomputing it would only risk disagreeing.
	memset(&t, 0, sizeof(t));
	memset(txns, 0, sizeof(txns));
	txns[0].txn_data_binary = plain; txns[0].size = sizeof(plain);
	t.txns = txns; t.txn_count = 1; t.coinbasevalue = 315541319; t.from_enforcer = false;
	strcpy(t.default_witness_commitment, stale);
	json_t *none = json_array();
	json_array_append_new(none, json_pack("{s:[]}", "depends"));
	datum_test(drop_unanswerable_bmm_requests(&t, none));
	datum_test(!strcmp(t.default_witness_commitment, stale));
	json_decref(none);
	printf("  a template that lost nothing keeps the node's commitment\n");
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


// Bitcoin Cash II turned SegWit off: its templates have no witness commitment
// and do not list the rule. Such a template parses, and the coinbase built from
// it declares exactly the outputs it carries, with no commitment among them.
static void a_chain_without_segwit_gets_a_coinbase_without_the_commitment(void) {
	if (!datum_test(datum_template_init() > 0)) return;
	const char *fmt =
	    "{\"height\":82182,\"coinbasevalue\":5000000000,\"rules\":[%s],"
	    "\"mintime\":1790032394,\"curtime\":1790033442,\"version\":536870912,\"sigoplimit\":640000,"
	    "\"bits\":\"19015d12\",\"sizelimit\":32000000,\"weightlimit\":32000000,"
	    "\"previousblockhash\":\"00000000000000017763f0d61fc6c8fc433537a54cfb3f2d09a5273d35a080e8\","
	    "\"target\":\"00000000000000015d1200000000000000000000000000000000000000000000\","
	    "\"transactions\":[]}";
	char gbt[2048];
	json_error_t err;

	snprintf(gbt, sizeof(gbt), fmt, "\"csv\"");
	json_t *j = json_loads(gbt, 0, &err);
	if (!datum_test(j != NULL)) { printf("  (fixture: %s)\n", err.text); return; }
	T_DATUM_TEMPLATE_DATA *t = datum_gbt_parser(j);
	datum_test(t != NULL && t->default_witness_commitment[0] == 0);
	json_decref(j);

	// A chain that does enforce SegWit still has to send the commitment.
	snprintf(gbt, sizeof(gbt), fmt, "\"csv\",\"!segwit\"");
	j = json_loads(gbt, 0, &err);
	if (!datum_test(j != NULL)) return;
	datum_test(datum_gbt_parser(j) == NULL);
	json_decref(j);
	printf("  a template without SegWit parses; one with it still needs the commitment\n");

	static T_DATUM_STRATUM_JOB job;
	static T_DATUM_TEMPLATE_DATA tpl;
	memset(&job, 0, sizeof(job));
	memset(&tpl, 0, sizeof(tpl));
	job.block_template = &tpl;
	job.coinbase_value = 50ULL * 100000000ULL;
	job.pool_addr_script_len = 25;
	job.pool_addr_script[0] = 0x76; job.pool_addr_script[1] = 0xa9; job.pool_addr_script[2] = 0x14;
	for (int k = 0; k < 60; k++) {
		job.available_coinbase_outputs[k].output_script_len = 25;
		job.available_coinbase_outputs[k].output_script[0] = 0x76;
		job.available_coinbase_outputs[k].output_script[1] = 0xa9;
		job.available_coinbase_outputs[k].output_script[2] = 0x14;
		job.available_coinbase_outputs[k].value_sats = 10000000ULL;
	}
	job.available_coinbase_outputs_count = 60;
	int mismatches = 0;
	for (int budget = 200; budget <= 2600; budget++) {
		int cb1idx[MAX_COINBASE_TYPES] = { 0 }, cb2idx[MAX_COINBASE_TYPES] = { 0 };
		job.coinbase[1].coinb2[0] = 0;
		generate_coinbase_txns_for_stratum_job_subtypebysize(&job, 1, budget, true, cb1idx, cb2idx, false);
		int declared = -1, trailing = -1;
		int actual = coinb2_outputs(job.coinbase[1].coinb2, &declared, &trailing);
		if (actual != declared || trailing != 4) mismatches++;
		datum_test(strstr(job.coinbase[1].coinb2, "6a24aa21a9ed") == NULL);
	}
	datum_test(mismatches == 0);
	printf("  and its coinbase declares exactly the outputs it carries (%d mismatched)\n", mismatches);
}

// Both from eCash. The first is an ordinary payment whose input spends a coin
// with a txid ending 6a2100bf ahead of output index 0 -- the byte scan reads
// that as a bid. The second is a real one (08136d63... in block 971,000).
static void unhex_into(const char *hex, uint8_t *out, uint32_t *n) {
	*n = strlen(hex) >> 1;
	for (uint32_t i = 0; i < *n; i++) out[i] = hex2bin_uchar(&hex[i * 2]);
}

static void a_bid_is_read_from_the_outputs_not_from_a_hash(void) {
	static const char *not_a_bid =
		"02000000000101f718311c0ff7e20c15c2f0e85a0bdf6936c2872ce767f22398e1dcd26a"
		"2100bf0000000000ffffffff03f40f01000000000016001497d546467169baa1b12b05ca"
		"045cdaebb5228a7a18010000000000000451024e730000000000000000156a5d12140114"
		"00ff7f818cec82d08bc0a88281d2150247304402205f74e53f686216a563a1fd9bd23304"
		"e84e4457f0da023e71c916014ea40bd126022001c482fab3c82c69dce4942e5fd39bde2d"
		"2784efcf7d2f571867c2d5cab4b65b01210214b6accd4877428d51737c6ac7210ff7d613"
		"29edb7ccced799e9821e962a837c00000000";
	static const char *a_bid =
		"02000000000101cb7ab3678477b0fdc9372c7a12e7428bea8d9a2d418aa88bddb80fdeef"
		"009de40100000000fdffffff020000000000000000466a4400bf0082fedcdb4f7faa173e"
		"dcbec8d48ebc2c5cddff1122faf5e4728f2fc7edca33c6b8136e0def59b58d5796566013"
		"0e65fde22edb567237d1cc1d0000000000000000c22a1006000000001600141e797f234d"
		"6c9b0022e4c7eb6624c8ab23710ad90247304402202eb2a2b635f97e11898c8b92044891"
		"df34d94d935b96cd836c653ba3046d9d4702201ec070c31af523f362701f154b000b415c"
		"a20178835ea0c201190c6a7e85cded01210226c83fee09f0ef66958348d3d4d76bd701c4"
		"7bcd8741a437ab1c26fd1ac53d1500000000";
	uint8_t b[512];
	uint32_t n;

	unhex_into(not_a_bid, b, &n);
	datum_test(txn_is_bmm_request(b, n));           // the scan is fooled
	datum_test(!txn_has_bmm_request_output(b, n));  // the outputs are not

	unhex_into(a_bid, b, &n);
	datum_test(txn_is_bmm_request(b, n));
	datum_test(txn_has_bmm_request_output(b, n));

	// Cut short, it cannot be read, and the scan answers instead -- which for
	// these bytes still finds the bid.
	datum_test(txn_has_bmm_request_output(b, 120) == txn_is_bmm_request(b, 120));
	datum_test(txn_has_bmm_request_output(b, 120));
	printf("  a bid is read from the outputs, not from a hash that looks like one\n");
}


static void put_commitment(T_DATUM_STRATUM_JOB *job, const char *hex) {
	T_DATUM_TXN_COMMITMENT *c = &job->commitments[job->commitments_count++];
	const int n = strlen(hex) / 2;
	for (int i = 0; i < n; i++) c->output_script[i] = hex2bin_uchar(&hex[i * 2]);
	c->output_script_len = n;
	job->commitments_size += 8 + (n < 0xFD ? 1 : 3) + n;
}

// An M1 proposal: OP_RETURN, PUSHDATA2 of 1,350 bytes, tag d5e0c4af.
static void put_proposal(T_DATUM_STRATUM_JOB *job) {
	T_DATUM_TXN_COMMITMENT *c = &job->commitments[job->commitments_count++];
	const int body = 1350;
	c->output_script[0] = 0x6a; c->output_script[1] = 0x4d;
	c->output_script[2] = body & 0xff; c->output_script[3] = body >> 8;
	c->output_script[4] = 0xd5; c->output_script[5] = 0xe0; c->output_script[6] = 0xc4; c->output_script[7] = 0xaf;
	memset(&c->output_script[8], 0x11, body - 4);
	c->output_script_len = 4 + body;
	job->commitments_size += 8 + 3 + c->output_script_len;
}

#define HEX_M7 "6a24d1617368" "0202020202020202020202020202020202020202020202020202020202020202"
#define HEX_M7B "6a24d1617368" "0303030303030303030303030303030303030303030303030303030303030303"
#define HEX_M4 "6a07d77d17760100ff"
#define HEX_M2 "6a24d6e1c5df" "0404040404040404040404040404040404040404040404040404040404040404"

// A small coinbase used to take a commitment set whole or not at all: one
// proposal in the set, or enough acks, and the accepts went with it, so every
// client on that type got empty work for every block with a bid. Now the
// accepts go first, all of them or none, then votes, acks, bundles and
// proposals while they fit.
static void commitments_are_packed_by_rank(void) {
	static T_DATUM_STRATUM_JOB job;
	memset(&job, 0, sizeof(job));
	put_proposal(&job);               // 0: M1, 1,361 bytes
	put_commitment(&job, HEX_M2);     // 1: M2, 47
	put_commitment(&job, HEX_M7);     // 2: M7, 47
	put_commitment(&job, HEX_M4);     // 3: M4, 18
	put_commitment(&job, HEX_M7B);    // 4: M7, 47
	bool use[DATUM_MAX_COMMITMENTS];
	int count, size;

	// Room for the accepts, the vote and the ack, not the proposal.
	datum_test(datum_commitments_pack(&job, 300, use, &count, &size) == 2);
	datum_test(!use[0] && use[1] && use[2] && use[3] && use[4]);
	datum_test(count == 4 && size == 47 + 47 + 18 + 47);
	// Room for the accepts and the vote only: the ack waits.
	datum_test(datum_commitments_pack(&job, 47 + 47 + 18, use, &count, &size) == 2);
	datum_test(!use[0] && !use[1] && use[2] && use[3] && use[4]);
	// Room for one accept, not both: neither goes in, and the type is marked
	// as not carrying them; what fits of the rest still does.
	datum_test(datum_commitments_pack(&job, 60, use, &count, &size) == 0);
	datum_test(!use[2] && !use[4] && use[3] && count == 1 && size == 18);
	// Room for everything: everything.
	datum_test(datum_commitments_pack(&job, 5000, use, &count, &size) == 2);
	datum_test(count == 5 && size == job.commitments_size);
	// No accepts at all: carried trivially.
	static T_DATUM_STRATUM_JOB votes;
	memset(&votes, 0, sizeof(votes));
	put_commitment(&votes, HEX_M4);
	datum_test(datum_commitments_pack(&votes, 0, use, &count, &size) == 0 && count == 0);

	// In a coinbase type: a proposal too large for it no longer takes the
	// accepts out with it, and the output count matches what is written.
	static T_DATUM_TEMPLATE_DATA tpl;
	memset(&tpl, 0, sizeof(tpl));
	memset(tpl.default_witness_commitment, 'a', 64);
	job.block_template = &tpl;
	job.coinbase_value = 1000ULL * 100000000ULL;
	job.pool_addr_script_len = 22;
	job.pool_addr_script[0] = 0x00; job.pool_addr_script[1] = 0x14;
	int cb1idx[MAX_COINBASE_TYPES] = { 0 }, cb2idx[MAX_COINBASE_TYPES] = { 0 };
	generate_coinbase_txns_for_stratum_job_subtypebysize(&job, 1, 300, true, cb1idx, cb2idx, false);
	datum_test(job.coinbase[1].accepts == 2);
	datum_test(strstr(job.coinbase[1].coinb2, "d1617368") != NULL);
	datum_test(strstr(job.coinbase[1].coinb2, "d77d1776") != NULL);
	datum_test(strstr(job.coinbase[1].coinb2, "d5e0c4af") == NULL);
	int declared = -1, trailing = -1;
	datum_test(coinb2_outputs(job.coinbase[1].coinb2, &declared, &trailing) == declared && trailing == 4);
	printf("  a small coinbase carries the BMM accepts first, then what else fits by rank\n");
}

// Coinbase 0 is what every client mines until the coinbaser lands, and for the
// whole of a job that never runs it. It carries the template's commitments as
// far as they fit, so that work is not empty for every block with a bid.
// And the subsidy-only coinbase is rebuilt whenever the coinbases are, from
// what holds then: built once at job creation, it kept an old payout script
// and, after the pool link changed, the PoT byte in the wrong place.
static void the_plain_coinbase_carries_commitments_and_the_empty_one_is_current(void) {
	static T_DATUM_STRATUM_JOB job;
	static T_DATUM_TEMPLATE_DATA tpl;
	memset(&job, 0, sizeof(job));
	memset(&tpl, 0, sizeof(tpl));
	memset(tpl.default_witness_commitment, 'a', 64);
	char saved_addr[sizeof(datum_config.mining_pool_address)];
	memcpy(saved_addr, datum_config.mining_pool_address, sizeof(saved_addr));
	strcpy(datum_config.mining_pool_address, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
	tpl.sizelimit = 4000000;
	tpl.weightlimit = 4000000;
	job.block_template = &tpl;
	job.height = 900000;
	job.coinbase_value = 4 * 100000000ULL;
	put_commitment(&job, HEX_M7);
	put_commitment(&job, HEX_M4);
	put_proposal(&job);

	generate_base_coinbase_txns_for_stratum_job(&job, false);
	datum_test(job.coinbase[0].accepts == 1);
	datum_test(strstr(job.coinbase[0].coinb2, "d1617368") != NULL);
	datum_test(strstr(job.coinbase[0].coinb2, "d77d1776") != NULL);
	datum_test(strstr(job.coinbase[0].coinb2, "d5e0c4af") == NULL);
	int declared = -1, trailing = -1;
	datum_test(coinb2_outputs(job.coinbase[0].coinb2, &declared, &trailing) == declared && trailing == 4);
	datum_test(declared == 4); // the accept, the vote, us, the witness commitment
	// The empty work's coinbase: our output alone, the subsidy, no commitments.
	datum_test(strstr(job.subsidy_only_coinbase.coinb2, "d1617368") == NULL);
	datum_test(coinb2_outputs(job.subsidy_only_coinbase.coinb2, &declared, &trailing) == 1 && declared == 1 && trailing == 4);
	datum_test(job.subsidy_only_coinbase.coinb2_len * 2 == (int)strlen(job.subsidy_only_coinbase.coinb2));
	datum_test(strstr(job.subsidy_only_coinbase.coinb2, "0014e8df018c7e326cc253faac7e46cdc51e68542c42") != NULL);

	// The coinbaser lands, with an accept of the pool's merged into the set
	// and the payout address changed meanwhile. Work on coinbase 0 and on the
	// empty coinbase was handed out already: their bytes stay exactly as they
	// were, so shares on that work still check out after it lands. The sized
	// types are built from what holds now.
	static T_DATUM_STRATUM_COINBASE before0, before_sub;
	memcpy(&before0, &job.coinbase[0], sizeof(before0));
	memcpy(&before_sub, &job.subsidy_only_coinbase, sizeof(before_sub));
	put_commitment(&job, HEX_M7B);
	strcpy(datum_config.mining_pool_address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
	generate_coinbase_txns_for_stratum_job(&job, false);
	datum_test(memcmp(&before0, &job.coinbase[0], sizeof(before0)) == 0);
	datum_test(memcmp(&before_sub, &job.subsidy_only_coinbase, sizeof(before_sub)) == 0);
	datum_test(strstr(job.coinbase[1].coinb2, "0014751e76e8199196d454941c45d1b3a323f1433bd6") != NULL);
	// Coinbase 0 has one of the job's two accepts now: with the bid in the
	// block it is not served; type 1, built with both, is.
	job.has_bmm_request = true;
	datum_test(job.bmm_accepts == 2);
	datum_test(job.coinbase[0].accepts == 1 && !datum_job_coinbase_is_safe(&job, 0));
	datum_test(job.coinbase[1].accepts == 2 && datum_job_coinbase_is_safe(&job, 1));

	memcpy(datum_config.mining_pool_address, saved_addr, sizeof(saved_addr));
	printf("  coinbase 0 carries the template's commitments, and it and the empty coinbase never change once handed out\n");
}

// The pool link changed between a job and its coinbaser: the other types
// become copies of coinbase 0, which itself (and the empty coinbase) is left
// exactly as handed out. Safe only because the types were not handed out yet
// (see the comment at the copy).
static void a_link_flip_leaves_the_job_on_coinbase_0(void) {
	static T_DATUM_STRATUM_JOB job;
	static T_DATUM_TEMPLATE_DATA tpl;
	static T_DATUM_STRATUM_COINBASE before0, before_sub;
	memset(&job, 0, sizeof(job));
	memset(&tpl, 0, sizeof(tpl));
	char saved_addr[sizeof(datum_config.mining_pool_address)];
	memcpy(saved_addr, datum_config.mining_pool_address, sizeof(saved_addr));
	strcpy(datum_config.mining_pool_address, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
	tpl.sizelimit = 4000000;
	tpl.weightlimit = 4000000;
	job.block_template = &tpl;
	job.height = 900000;
	job.coinbase_value = 4 * 100000000ULL;
	generate_base_coinbase_txns_for_stratum_job(&job, false);
	memcpy(&before0, &job.coinbase[0], sizeof(before0));
	memcpy(&before_sub, &job.subsidy_only_coinbase, sizeof(before_sub));
	// Made while the pool was up; the pool is down when the coinbaser lands.
	datum_test(!datum_protocol_is_active());
	job.is_datum_job = true;
	generate_coinbase_txns_for_stratum_job(&job, false);
	datum_test(memcmp(&before0, &job.coinbase[0], sizeof(before0)) == 0);
	datum_test(memcmp(&before_sub, &job.subsidy_only_coinbase, sizeof(before_sub)) == 0);
	for (int t = 1; t < MAX_COINBASE_TYPES; t++) {
		datum_test(memcmp(&job.coinbase[t], &job.coinbase[0], sizeof(job.coinbase[0])) == 0);
	}
	memcpy(datum_config.mining_pool_address, saved_addr, sizeof(saved_addr));
	printf("  after a link flip every type is coinbase 0, which is unchanged\n");
}

// A refused template for a new block used to keep the previous job, leaving
// every miner on the block before. Its header is enough for empty work: a
// block with no transactions, no commitments and the subsidy alone.
static void a_refused_template_still_moves_miners_to_the_new_block(void) {
	if (!datum_test(datum_template_init() > 0)) return;
	// An enforcer template (coinbasetxn, from the alphanet enforcer) over
	// 16383 transactions: refused before a transaction is read.
	static const char *cbtxn =
		"020000000001010000000000000000000000000000000000000000000000000000000000"
		"000000ffffffff04035d340fffffffff027b95c912000000001600141f8cf1fd34d0c377"
		"0c58023f1f0f7750b2dd18c30000000000000000266a24aa21a9ed52aeb9bd30449a1502"
		"50bd83cfc5aa41ac7526f50fff47ce76963b66cb02259b01200000000000000000000000"
		"00000000000000000000000000000000000000000000000000";
	const int ntx = 16384;
	char *gbt = malloc(4096 + ntx * 3);
	if (!datum_test(gbt != NULL)) return;
	int n = snprintf(gbt, 4096,
	    "{\"height\":996445,\"coinbasevalue\":315200891,\"coinbasetxn\":{\"data\":\"%s\"},"
	    "\"mintime\":1788470000,\"curtime\":1788470100,\"version\":536870912,\"sigoplimit\":80000,"
	    "\"bits\":\"1d00ffff\",\"sizelimit\":4000000,\"weightlimit\":4000000,"
	    "\"previousblockhash\":\"0000000000000000e371b1e760aa93bcaa309f626beb59bff6c61f3e56443d48\","
	    "\"target\":\"00000000ffff0000000000000000000000000000000000000000000000000000\","
	    "\"default_witness_commitment\":\"6a24aa21a9ed52aeb9bd30449a150250bd83cfc5aa41ac7526f50fff47ce76963b66cb02259b\","
	    "\"transactions\":[", cbtxn);
	for (int i = 0; i < ntx; i++) n += sprintf(&gbt[n], i ? ",{}" : "{}");
	strcpy(&gbt[n], "]}");
	json_error_t err;
	json_t *j = json_loads(gbt, 0, &err);
	free(gbt);
	if (!datum_test(j != NULL)) { printf("  (fixture: %s)\n", err.text); return; }
	datum_test(datum_gbt_parser(j) == NULL);
	
	T_DATUM_TEMPLATE_DATA *e = datum_gbt_header_template(j);
	json_decref(j);
	if (!datum_test(e != NULL)) return;
	datum_test(e->height == 996445);
	datum_test(!strcmp(e->previousblockhash, "0000000000000000e371b1e760aa93bcaa309f626beb59bff6c61f3e56443d48"));
	datum_test(e->previousblockhash_bin[0] == 0x48 && e->bits_uint == 0x1d00ffff && e->curtime == 1788470100 && e->mintime == 1788470000);
	datum_test(e->txn_count == 0 && e->commitments_count == 0 && !e->from_enforcer && !e->bmm_accepts_dropped);
	datum_test(e->default_witness_commitment[0] == 0);
	// The subsidy alone: the node's value carries fees this block will not.
	datum_test(e->coinbasevalue == block_reward(996445) || e->coinbasevalue == 315200891ULL);
	datum_test(e->coinbasevalue <= block_reward(996445) && e->coinbasevalue <= 315200891ULL);
	
	// A job on it, as update_stratum_job makes one: no bid, no accept, every coinbase safe, and
	// coinbase 0 (what a client connecting meanwhile gets) pays only what the empty coinbase does.
	static T_DATUM_STRATUM_JOB job;
	memset(&job, 0, sizeof(job));
	char saved_addr[sizeof(datum_config.mining_pool_address)];
	memcpy(saved_addr, datum_config.mining_pool_address, sizeof(saved_addr));
	strcpy(datum_config.mining_pool_address, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
	job.block_template = e;
	job.height = e->height;
	job.coinbase_value = e->coinbasevalue;
	commitments_from_template(&job);
	datum_job_note_bmm_request(&job);
	datum_job_note_bmm_accept(&job);
	generate_base_coinbase_txns_for_stratum_job(&job, true);
	datum_test(job.commitments_count == 0 && !job.has_bmm_request && job.bmm_accepts == 0);
	datum_test(datum_job_coinbase_is_safe(&job, 0));
	int declared = -1, trailing = -1;
	datum_test(coinb2_outputs(job.coinbase[0].coinb2, &declared, &trailing) == 1 && declared == 1 && trailing == 4);
	datum_test(coinb2_outputs(job.subsidy_only_coinbase.coinb2, &declared, &trailing) == 1 && declared == 1);
	char value_hex[17];
	snprintf(value_hex, sizeof(value_hex), "%016llx", (unsigned long long)__builtin_bswap64(e->coinbasevalue));
	datum_test(strstr(job.coinbase[0].coinb2, value_hex) != NULL);
	memcpy(datum_config.mining_pool_address, saved_addr, sizeof(saved_addr));
	
	// A header that is itself broken gives nothing to build on: the old job stays.
	j = json_loads("{\"height\":5,\"mintime\":1,\"curtime\":2,\"version\":1,\"sigoplimit\":1,"
	               "\"sizelimit\":1,\"weightlimit\":1,\"bits\":\"1d00ffff\",\"transactions\":[]}", 0, &err);
	if (datum_test(j != NULL)) {
		datum_test(datum_gbt_header_template(j) == NULL);
		json_decref(j);
	}
	
	// When: at once on a new block; on the same block, a fresh empty job once per work
	// update while on one, and a full job kept until its shares would go stale.
	datum_test(datum_template_refusal_action(true, false, 0, 39000, 120000) == DATUM_REFUSAL_EMPTY_NEW_BLOCK);
	datum_test(datum_template_refusal_action(true, true, 0, 39000, 120000) == DATUM_REFUSAL_EMPTY_NEW_BLOCK);
	datum_test(datum_template_refusal_action(false, true, 250, 39000, 120000) == DATUM_REFUSAL_KEEP);
	datum_test(datum_template_refusal_action(false, true, 40000, 39000, 120000) == DATUM_REFUSAL_EMPTY_REFRESH);
	datum_test(datum_template_refusal_action(false, false, 80000, 39000, 120000) == DATUM_REFUSAL_KEEP);
	datum_test(datum_template_refusal_action(false, false, 120000, 39000, 120000) == DATUM_REFUSAL_EMPTY_REFRESH);
	printf("  a refused template for a new block still moves miners to it, on empty work\n");
}

void datum_blocktemplates_tests(void) {
	a_refused_template_still_moves_miners_to_the_new_block();
	a_chain_without_segwit_gets_a_coinbase_without_the_commitment();
	the_parser_drops_bids_when_there_is_no_enforcer();
	a_template_without_an_enforcer_drops_the_bmm_bids();
	dropping_a_bid_rewrites_the_witness_commitment();
	the_pool_can_ack_more_than_one_proposal();
	a_template_with_its_own_accepts_ignores_the_pools();
	a_malformed_pool_payload_leaves_the_template_whole();
	pool_commitments_follow_chains_rules();
	the_output_count_matches_the_outputs_written();
	commitments_are_packed_by_rank();
	a_link_flip_leaves_the_job_on_coinbase_0();
	the_plain_coinbase_carries_commitments_and_the_empty_one_is_current();
	an_m4_of_the_wrong_length_is_recognised();
	the_pool_vote_replaces_the_templates_vote_of_the_same_kind();
	a_skipped_template_commitment_leaves_no_hole();
	printf("BIP300/301 template tests:\n");
	take_the_value_and_the_commitments();
	a_coinbase_paying_nothing_is_refused();
	a_truncated_coinbase_is_refused();
	too_many_commitments_leaves_the_rest_out();
	a_proposal_fits();
	only_what_chains_reads_as_a_bid_is_one();
	a_pool_vote_has_to_fit_the_template();
	a_bmm_accept_needs_its_request_in_the_block();
	a_pool_sent_accept_is_checked_against_our_own_block();
	commitments_without_bmm_are_left_alone();
	a_real_enforcer_coinbase();
	a_bid_is_read_from_the_outputs_not_from_a_hash();
}
