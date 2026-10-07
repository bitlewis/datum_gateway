/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of OCEAN's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://ocean.xyz
 *
 * ---
 *
 * Copyright (c) 2024-2025 Bitcoin Ocean, LLC & Jason Hughes
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

// TODO: Empty work speedup work and an actual empty template will cause duplicate work.
// It's kind of unlikely that a sane miner would be purposefully providing empty templates, but
// this is a low priority bug to address nonetheless.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <curl/curl.h>
#include <inttypes.h>
#include <unistd.h>

#include "datum_conf.h"
#include "datum_utils.h"
#include "datum_stratum.h"
#include "datum_jsonrpc.h"
#include "datum_protocol.h"
#include "datum_coinbaser.h"

CURL *coinbaser_curl = NULL;

const char *cbstart_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff"; // 82 len hex, 41 bytes

// The witness commitment output, when there is one. A chain that turned SegWit
// off (Bitcoin Cash II) sends a template without one, and its blocks carry no
// such output: the coinbase is one output shorter throughout.
void datum_job_note_bmm_accept(T_DATUM_STRATUM_JOB *s);

static inline int witness_outputs(const T_DATUM_STRATUM_JOB *s) {
	return s->block_template->default_witness_commitment[0] ? 1 : 0;
}

#define MAX_COINBASE_TAG_SPACE 86 // leaves space for BIP34 height, extranonces, datum prime tag, etc.

int generate_coinbase_input(int height, char *cb, int *target_pot_index) {
	int cb_input_sz = 0;
	int tag_len[2] = { 0, 0 };
	int k, m, i;
	int excess;
	bool datum_active = false;
	
	// let's figure out our coinbase tags w/BIP34 height
	i = append_bip34_height_hex(height, &cb[0]);
	cb_input_sz += i>>1;
	
	datum_active = datum_protocol_is_active();
	
	// Handle coinbase tagging
	// The first push after the height should be:
	// PUSHBYTES X, Primary tag, 0x0F, Secondary tag, 0x0F, Tertiary tag, 0x00
	// We should then push a unique entropy tag (push + 2 bytes = 3 bytes)
	if (!datum_active) {
		tag_len[0] = strlen(datum_config.mining_coinbase_tag_primary);
	} else {
		tag_len[0] = strlen(datum_config.override_mining_coinbase_tag_primary);
	}
	tag_len[1] = strlen(datum_config.mining_coinbase_tag_secondary);
	k = tag_len[0] + tag_len[1] + 2;
	if (!tag_len[1]) {
		k--;
		if (!tag_len[0]) {
			k--;
		}
	}
	
	if (k > MAX_COINBASE_TAG_SPACE) {
		// something still needs truncating
		excess = k - MAX_COINBASE_TAG_SPACE;
		if (tag_len[1] > excess) {
			// truncating tag1 is enough to cover us
			tag_len[1] -= excess;
			k = MAX_COINBASE_TAG_SPACE;
		} else {
			// not enough, so need to remove this tag entirely
			if (tag_len[1]) {
				tag_len[1] = 0;
				k-=tag_len[1]+1;
			}
		}
	}
	
	if (k > MAX_COINBASE_TAG_SPACE) {
		// one tag should never exceed 64 bytes, so we're going to panic here.
		DLOG_FATAL("Could not fit coinbase primary tag alone somehow. This is probably a bug. Panicking. :(");
		panic_from_thread(__LINE__);
		sleep(1000000);
	}
	
	if (k > 0) {
		// ok, we have one or more coinbase tags with a total len of k
		if (k <= 75) {
			// OP_PUSHBYTES (1 byte, 1 to 75)
			uchar_to_hex(&cb[i], (unsigned char)k); i+=2; cb_input_sz++;
		} else {
			// OP_PUSHBYTES (2 byte, 76 to 94)
			uchar_to_hex(&cb[i], 0x4C); i+=2; cb_input_sz++;
			uchar_to_hex(&cb[i], (unsigned char)k); i+=2; cb_input_sz++;
		}
		
		if (tag_len[0]) {
			if (datum_active) {
				for(m=0;m<tag_len[0];m++) {
					uchar_to_hex(&cb[i], (unsigned char)datum_config.override_mining_coinbase_tag_primary[m]); i+=2; cb_input_sz++;
				}
			} else {
				for(m=0;m<tag_len[0];m++) {
					uchar_to_hex(&cb[i], (unsigned char)datum_config.mining_coinbase_tag_primary[m]); i+=2; cb_input_sz++;
				}
			}
			if (!tag_len[1]) {
				uchar_to_hex(&cb[i], 0x00); i+=2; cb_input_sz++;
			} else {
				uchar_to_hex(&cb[i], 0x0F); i+=2; cb_input_sz++;
			}
		} else {
			// we wouldn't be here if there wasn't at least one other
			if (tag_len[1]) {
				uchar_to_hex(&cb[i], 0x0F); i+=2; cb_input_sz++;
			}
		}
		
		if (tag_len[1]) {
			for(m=0;m<tag_len[1];m++) {
				uchar_to_hex(&cb[i], (unsigned char)datum_config.mining_coinbase_tag_secondary[m]); i+=2; cb_input_sz++;
			}
			uchar_to_hex(&cb[i], 0x00); i+=2; cb_input_sz++;
		}
	} else {
		// we'll push a null char to be consistent, and to not parse the UID as if it were a pool name
		uchar_to_hex(&cb[i], 0x01); i+=2; cb_input_sz++;
		uchar_to_hex(&cb[i], 0x00); i+=2; cb_input_sz++;
	}
	
	// append the coinbase unique ID tag
	if ((datum_config.prime_id == 0) && (!datum_active)) {
		uchar_to_hex(&cb[i], 0x03); i+=2; cb_input_sz++;
		if (target_pot_index != NULL) *target_pot_index = cb_input_sz;
		uchar_to_hex(&cb[i], 0xFF); i+=2; cb_input_sz++; // placehodler for PoT target
		uchar_to_hex(&cb[i], (datum_config.coinbase_unique_id&0xFF)); i+=2; cb_input_sz++;
		uchar_to_hex(&cb[i], ((datum_config.coinbase_unique_id>>8)&0xFF)); i+=2; cb_input_sz++;
	} else {
		uchar_to_hex(&cb[i], 0x07); i+=2; cb_input_sz++;
		if (target_pot_index != NULL) *target_pot_index = cb_input_sz;
		uchar_to_hex(&cb[i], 0xFF); i+=2; cb_input_sz++; // placeholder for PoT target
		uchar_to_hex(&cb[i], (datum_config.coinbase_unique_id&0xFF)); i+=2; cb_input_sz++;
		uchar_to_hex(&cb[i], ((datum_config.coinbase_unique_id>>8)&0xFF)); i+=2; cb_input_sz++;
		uchar_to_hex(&cb[i], (datum_config.prime_id&0xFF)); i+=2; cb_input_sz++;
		uchar_to_hex(&cb[i], ((datum_config.prime_id>>8)&0xFF)); i+=2; cb_input_sz++;
		uchar_to_hex(&cb[i], ((datum_config.prime_id>>16)&0xFF)); i+=2; cb_input_sz++;
		uchar_to_hex(&cb[i], ((datum_config.prime_id>>24)&0xFF)); i+=2; cb_input_sz++;
	}
	
	return cb_input_sz;
}

// Where a commitment ranks when a coinbase cannot carry them all: by what is
// lost without it. A BMM accept (M7) answers a bid that is a transaction of
// the same block, which without it is invalid on the drivechain; then a vote
// (M4), an ack (M2), a bundle (M3), a proposal (M1), and anything else.
static int commitment_rank(const unsigned char *script, int len) {
	static const unsigned char tags[5][4] = {
		{ 0xd1, 0x61, 0x73, 0x68 }, // M7, BMM accept
		{ 0xd7, 0x7d, 0x17, 0x76 }, // M4, vote on bundles
		{ 0xd6, 0xe1, 0xc5, 0xdf }, // M2, ack of a proposed sidechain
		{ 0xd4, 0x5a, 0xa9, 0x43 }, // M3, bundle
		{ 0xd5, 0xe0, 0xc4, 0xaf }, // M1, sidechain proposal
	};
	unsigned char tag[4];
	if (datum_commitment_tag(script, len, tag)) {
		for (int r = 0; r < 5; r++) {
			if (!memcmp(tag, tags[r], 4)) return r;
		}
	}
	return 5;
}

static int commitment_bytes(const T_DATUM_TXN_COMMITMENT *c) {
	// 8 bytes of value, the script's length prefix, then the script.
	return 8 + (c->output_script_len < 0xFD ? 1 : 3) + c->output_script_len;
}

bool datum_commitments_pack(const T_DATUM_STRATUM_JOB *s, int budget, bool *use, int *count, int *size) {
	// Written as hex into coinb2, which has a size of its own.
	const int hex_room = (STRATUM_COINBASE2_MAX_LEN - 1024) / 2;
	if (budget > hex_room) budget = hex_room;
	*count = 0;
	*size = 0;
	int accepts = 0, accepts_size = 0;
	for (int k = 0; k < s->commitments_count; k++) {
		use[k] = false;
		if (commitment_rank(s->commitments[k].output_script, s->commitments[k].output_script_len) == 0) {
			accepts++;
			accepts_size += commitment_bytes(&s->commitments[k]);
		}
	}
	// The accepts all go in, or none: one left out with its bid in the block
	// is as bad as all of them, and the job is then not served on this type.
	bool carried = (accepts == 0);
	if (accepts > 0 && accepts_size <= budget) {
		for (int k = 0; k < s->commitments_count; k++) {
			if (commitment_rank(s->commitments[k].output_script, s->commitments[k].output_script_len) == 0) use[k] = true;
		}
		*count = accepts;
		*size = accepts_size;
		carried = true;
	}
	// Then each of the others in rank order, while it fits. One that does not
	// is a vote, an ack or a proposal this block does not make, which is legal.
	for (int r = 1; r <= 5; r++) {
		for (int k = 0; k < s->commitments_count; k++) {
			if (commitment_rank(s->commitments[k].output_script, s->commitments[k].output_script_len) != r) continue;
			const int b = commitment_bytes(&s->commitments[k]);
			if (*size + b > budget) continue;
			use[k] = true;
			(*count)++;
			*size += b;
		}
	}
	return carried;
}

void generate_coinbase_txns_for_stratum_job_subtypebysize(T_DATUM_STRATUM_JOB *s, int coinbase_index, int remaining_size, bool space_for_en_in_coinbase, int *cb1idx, int *cb2idx, bool special_coinb1) {
	// This function finishes off the stratum coinb1+coinb2 using the available outputs in the job and other flags specified.
	// it does not attempt to maximize coinb1's size to any specific size
	
	int i, j, k, m, i2 = 0, c1cnt = 0;
	uint64_t mval = 0;
	bool c1full = false;
	bool en_done = false;
	// chicken and egg problem.  we need to know the output count before we can close off coinb1 if !space_for_en_in_coinbase
	// either way, we want to start out coinb2 with outputs
	i = remaining_size;
	j = remaining_size;
	// Commitments come out of the budget before any payout is measured
	// against it. The loop below trims the payout list to fit a worker's
	// coinbase limit, which is right for payouts -- one that does not fit is
	// deferred and paid from a later block -- but a commitment that does not
	// fit is a vote that silently did not happen. So they are not in that
	// loop: their space is taken first and what remains is what payouts get.
	//
	// Taken from BOTH budgets. The count loop (i) and the emit loop (j) are
	// byte-identical on purpose, because the output count is written before
	// the outputs are: whatever the first loop counts, the second must write,
	// no more and no fewer. Reducing only i let the second loop fit payouts
	// the first had not counted, so once enough miners were owed that a
	// commitment displaced one, the coinbase declared fewer outputs than it
	// carried. That is an invalid block the gateway believes it found.
	//
	// As many as fit, by rank (datum_commitments_pack): every BMM accept or
	// none, then votes, acks, bundles and proposals. A low-capacity rig then
	// mines a block that carries the accepts and abstains on what did not fit,
	// rather than, as when the set went in whole or not at all, empty work for
	// every block with a bid once the set outgrew its coinbase.
	bool use[DATUM_MAX_COMMITMENTS];
	int commit_count = 0, commit_size = 0;
	s->coinbase[coinbase_index].carries_accepts = datum_commitments_pack(s, remaining_size, use, &commit_count, &commit_size);
	if (commit_count < s->commitments_count) {
		// Once per change, not once per job: a job is built every few
		// seconds and this condition can hold for a whole template.
		static int warned_size[MAX_COINBASE_TYPES];
		if (warned_size[coinbase_index] != s->commitments_size) {
			warned_size[coinbase_index] = s->commitments_size;
			DLOG_WARN("Coinbase type %d carries %d of %d commitment(s) (%d of %d bytes) in a %d byte budget%s",
			          coinbase_index, commit_count, s->commitments_count, commit_size, s->commitments_size, remaining_size,
			          s->coinbase[coinbase_index].carries_accepts ? "" : "; its BMM accepts did not fit, so this type gets empty work");
		}
	}
	i -= commit_size;
	j -= commit_size;
	if (special_coinb1) {
		i2 = (300 - cb1idx[coinbase_index])>>1;
		if (i2 < 0) i2 = 0;
		space_for_en_in_coinbase = false;
	}
	m = 0;
	mval = 0;
	// technically an output script could be > 0x4B, meaning an extra byte would be eaten here... but that's not currently the standard
	// this needs to match the loop lower in this function, as the count will get thrown off if it does not.
	
	// TODO: Enforce max sigops! Note: This is not currently enforced in eloipool, either, so punting for now and will monitor network stats to determine priority.
	for(k=0;k<s->available_coinbase_outputs_count;k++) {
		if (((s->available_coinbase_outputs[k].output_script_len+9) <= i) && ((mval + s->available_coinbase_outputs[k].value_sats) <= s->coinbase_value))  {
			if ((special_coinb1) && (!c1full) && ((s->available_coinbase_outputs[k].output_script_len+9) <= i2)) {
				i2 -= (s->available_coinbase_outputs[k].output_script_len+9);
				c1cnt++;
			} else {
				c1full = true;
			}
			
			i -= (s->available_coinbase_outputs[k].output_script_len+9);
			m++;
			mval += s->available_coinbase_outputs[k].value_sats;
			if (i < 30) break;
			if (mval >= s->coinbase_value) break;
		}
	}
	
	// "m" outputs fit
	m += commit_count;

	if (space_for_en_in_coinbase) {
		// we'll start the empty coinb2 with the "sequence"
		m += 1 + witness_outputs(s); // pool addr + witness
		pk_u64le(s->coinbase[coinbase_index].coinb2, cb2idx[coinbase_index], 0x6666666666666666ULL);  // "ffffffff"
		cb2idx[coinbase_index] = 8;
		cb2idx[coinbase_index] += append_bitcoin_varint_hex(m, &s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]]); // us, witness, and "m" outputs
	} else {
		m += 2 + witness_outputs(s);
		cb1idx[coinbase_index] += append_bitcoin_varint_hex(m, &s->coinbase[coinbase_index].coinb1[cb1idx[coinbase_index]]); // extranonce, us, witness commit, and "m" outputs
		
		if (!special_coinb1) {
			// append extranonce op_return
			cb1idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb1[cb1idx[coinbase_index]], "0000000000000000106a0e%04" PRIx16, s->enprefix);
			en_done = true;
		}
	}
	
	// append "m" payouts. find them the same way we did before
	mval = 0;
	for(k=0;k<s->available_coinbase_outputs_count;k++) {
		if (((s->available_coinbase_outputs[k].output_script_len+9) <= j) && ((mval + s->available_coinbase_outputs[k].value_sats) <= s->coinbase_value)) {
			j -= (s->available_coinbase_outputs[k].output_script_len+9);
			m--;
			
			mval += s->available_coinbase_outputs[k].value_sats;
			
			if ((special_coinb1) && (k < c1cnt)) {
				// put in coinb1
				cb1idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb1[cb1idx[coinbase_index]], "%016llx", (unsigned long long)__builtin_bswap64(s->available_coinbase_outputs[k].value_sats)); // TODO: Profile a faster way to do this
				cb1idx[coinbase_index] += append_bitcoin_varint_hex(s->available_coinbase_outputs[k].output_script_len, &s->coinbase[coinbase_index].coinb1[cb1idx[coinbase_index]]); // Append script length
				for(i=0;i<s->available_coinbase_outputs[k].output_script_len;i++) {
					uchar_to_hex(&s->coinbase[coinbase_index].coinb1[cb1idx[coinbase_index]], s->available_coinbase_outputs[k].output_script[i]);
					cb1idx[coinbase_index]+=2;
				}
			} else {
				if ((special_coinb1) && (k == c1cnt)) {
					// append extranonce op_return
					cb1idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb1[cb1idx[coinbase_index]], "0000000000000000106a0e%04" PRIx16, s->enprefix);
					en_done = true;
				}
				
				// put in coinb2
				cb2idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]], "%016llx", (unsigned long long)__builtin_bswap64(s->available_coinbase_outputs[k].value_sats)); // TODO: Profile a faster way to do this
				cb2idx[coinbase_index] += append_bitcoin_varint_hex(s->available_coinbase_outputs[k].output_script_len, &s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]]); // Append script length
				for(i=0;i<s->available_coinbase_outputs[k].output_script_len;i++) {
					uchar_to_hex(&s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]], s->available_coinbase_outputs[k].output_script[i]);
					cb2idx[coinbase_index]+=2;
				}
			}
			if (!m) break;
			if (j < 30) break;
			if (mval >= s->coinbase_value) break;
		}
	}
	
	// Commitments, written after the payouts and before the pool's own output.
	// Zero value, so they take nothing from miners; their cost is the bytes,
	// which were reserved out of the budget before payouts were counted.
	//
	// The bytes are the pool's, verbatim. Nothing here parses or validates
	// them: a gateway that understood BIP300 would need rebuilding every time
	// BIP300 gained a message, and the pool is the end that already knows.
	for (k = 0; k < s->commitments_count; k++) {
		if (!use[k]) continue;
		cb2idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]], "0000000000000000");
		cb2idx[coinbase_index] += append_bitcoin_varint_hex(s->commitments[k].output_script_len, &s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]]);
		for (i = 0; i < s->commitments[k].output_script_len; i++) {
			uchar_to_hex(&s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]], s->commitments[k].output_script[i]);
			cb2idx[coinbase_index] += 2;
		}
	}

	// this should never happen, but...
	if (mval > s->coinbase_value) {
		DLOG_ERROR("Attempting to pay more than we have available in the generation txn! --- %"PRIu64" sats available, %"PRIu64" sats to miners", s->coinbase_value, mval);
	}
	
	if ((!space_for_en_in_coinbase) && (!en_done)) {
		cb1idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb1[cb1idx[coinbase_index]], "0000000000000000106a0e%04" PRIx16, s->enprefix);
		en_done = true;
	}
	
	if (s->coinbase_value > mval) {
		// append our payout output value and script, since there are leftover funds
		cb2idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]], "%016llx", (unsigned long long)__builtin_bswap64(s->coinbase_value - mval)); // TODO: Profile a faster way to do this
		cb2idx[coinbase_index] += append_bitcoin_varint_hex(s->pool_addr_script_len, &s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]]); // Append script length
		for(i=0;i<s->pool_addr_script_len;i++) {
			uchar_to_hex(&s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]], s->pool_addr_script[i]);
			cb2idx[coinbase_index]+=2;
		}
	} else {
		// We paid every sat of the coinbase to miners... and saved an output.
		// HOWEVER....... we already locked in a number of outputs that presumes we would have a pool output
		// so tack on a dead output, sadly.
		// TODO: Make code smarter above, don't waste an output if we don't need it.
		// This is quite unlikely in practice, but, just in case let's make this a prunable OP_RETURN
		cb2idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]], "0000000000000000036a0100"); // TODO: Is a naked OP_RETURN without any bytes after safe?  Above TODO is probably better than investigating.
	}
	
	// witness commit output costs 46 bytes
	// append the default_witness_commitment
	if (witness_outputs(s)) cb2idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]], "0000000000000000%2.2x%s", (unsigned int)strlen(s->block_template->default_witness_commitment)>>1, s->block_template->default_witness_commitment);
	// lock time
	cb2idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]], "00000000");
}

int datum_stratum_coinbase_fit_to_template(int max_sz, int fixed_bytes, T_DATUM_STRATUM_JOB *s) {
	int j,i,msz1;
	
	i = fixed_bytes + max_sz;
	msz1 = max_sz+fixed_bytes;
	
	if ((i+s->block_template->txn_total_size+85+36) > s->block_template->sizelimit) {
		j = s->block_template->sizelimit - (s->block_template->txn_total_size+85+36) - fixed_bytes;
		if (j < 0) return 0;
		msz1 = j;
	}
	
	if (((i<<2)+s->block_template->txn_total_weight+340+36) > s->block_template->weightlimit) {
		j = ((s->block_template->weightlimit - (s->block_template->txn_total_weight+340+36))>>2) - fixed_bytes;
		if (j < 0) return 0;
		msz1 = j;
	}
	
	if (msz1 < 0) {
		msz1 = 0;
	}
	
	if (msz1 < (max_sz - fixed_bytes)) {
		return msz1;
	} else {
		return max_sz - fixed_bytes;
	}
}

// Coinbase 0, the plain one: the pool's (or our) output, the witness
// commitment, and the commitments that fit the smallest coinbase a client
// takes (type 1's); and, from the same start, the subsidy-only coinbase of
// empty work. Every client gets coinbase 0 until the coinbaser has built the
// others, and for the whole of a job that never runs it: with the
// commitments in it, that work carries the template's BMM accepts and votes
// instead of being served empty for every block with a bid.
//
// The subsidy-only coinbase is rebuilt with it every time, not only when a
// job is created: whether the pool is in use decides the coinbase's tags, and
// so where the PoT byte goes (target_pot_index, set by the caller) and whom
// it pays. Built from an earlier state, it had the byte in the wrong place.
static void build_plain_coinbase(T_DATUM_STRATUM_JOB *s, bool space_for_en_in_coinbase, int cb_input_sz, int *cb1idx, int *cb2idx) {
	T_DATUM_STRATUM_COINBASE *const sub = &s->subsidy_only_coinbase;
	int i, j = 0, k;
	bool use[DATUM_MAX_COMMITMENTS];
	int commit_count = 0, commit_size = 0;
	// Fixed bytes as for type 1 (see cb_req_sz in generate_coinbase_txns_for_stratum_job).
	const int req = 119 + s->pool_addr_script_len + cb_input_sz + (space_for_en_in_coinbase ? 0 : 10);
	s->coinbase[0].carries_accepts = datum_commitments_pack(s, datum_stratum_coinbase_fit_to_template(500, req, s), use, &commit_count, &commit_size);
	// Where the subsidy-only coinbase's own output starts in its coinb2.
	int sub2 = 0;
	
	if (space_for_en_in_coinbase) {
		// we'll start the empty coinb2 with the "sequence"
		pk_u64le(s->coinbase[0].coinb2, 0, 0x6666666666666666ULL);  // "ffffffff"
		cb2idx[0] = 8;
		cb2idx[0] += append_bitcoin_varint_hex(1 + witness_outputs(s) + commit_count, &s->coinbase[0].coinb2[cb2idx[0]]); // us, witness commit, commitments
		
		// copy the beginning to the subsidy-only, its end of string too
		memcpy(&sub->coinb1[0], &s->coinbase[0].coinb1[0], cb1idx[0] + 1);
		pk_u64le(sub->coinb2, 0, 0x6666666666666666ULL);  // "ffffffff"
		sub2 = 8 + append_bitcoin_varint_hex(1, &sub->coinb2[8]); // just us!
	} else {
		// we're already at the point in coinb1 where we need an output count
		j = cb1idx[0];
		cb1idx[0] += append_bitcoin_varint_hex(2 + witness_outputs(s) + commit_count, &s->coinbase[0].coinb1[cb1idx[0]]); // extranonce, us, witness commit, commitments
		
		// append extranonce op_return
		cb1idx[0] += sprintf(&s->coinbase[0].coinb1[cb1idx[0]], "0000000000000000106a0e%04" PRIx16, s->enprefix);
		
		// copy the beginning to the subsidy-only, its end of string too
		memcpy(&sub->coinb1[0], &s->coinbase[0].coinb1[0], cb1idx[0] + 1);
		k = append_bitcoin_varint_hex(2, &sub->coinb1[j]); // extranonce and us
		sub->coinb1[j+k] = s->coinbase[0].coinb1[j+k];
		cb2idx[0] = 0;
		sub2 = 0;
	}
	
	// The commitments, zero value, before our output as in the sized types.
	for (k = 0; k < s->commitments_count; k++) {
		if (!use[k]) continue;
		cb2idx[0] += sprintf(&s->coinbase[0].coinb2[cb2idx[0]], "0000000000000000");
		cb2idx[0] += append_bitcoin_varint_hex(s->commitments[k].output_script_len, &s->coinbase[0].coinb2[cb2idx[0]]);
		for (i = 0; i < s->commitments[k].output_script_len; i++) {
			uchar_to_hex(&s->coinbase[0].coinb2[cb2idx[0]], s->commitments[k].output_script[i]);
			cb2idx[0] += 2;
		}
	}
	
	// append our payout output value and script
	j = cb2idx[0];
	cb2idx[0] += sprintf(&s->coinbase[0].coinb2[cb2idx[0]], "%016llx", (unsigned long long)__builtin_bswap64(s->coinbase_value)); // TODO: Profile a faster way to do this
	cb2idx[0] += append_bitcoin_varint_hex(s->pool_addr_script_len, &s->coinbase[0].coinb2[cb2idx[0]]); // Append script length
	for(i=0;i<s->pool_addr_script_len;i++) {
		uchar_to_hex(&s->coinbase[0].coinb2[cb2idx[0]], s->pool_addr_script[i]);
		cb2idx[0]+=2;
	}
	k = cb2idx[0];
	
	// witness commit output costs 46 bytes
	// append the default_witness_commitment
	if (witness_outputs(s)) cb2idx[0] += sprintf(&s->coinbase[0].coinb2[cb2idx[0]], "0000000000000000%2.2x%s", (unsigned int)strlen(s->block_template->default_witness_commitment)>>1, s->block_template->default_witness_commitment);
	// lock time
	cb2idx[0] += sprintf(&s->coinbase[0].coinb2[cb2idx[0]], "00000000");
	
	// The subsidy-only payout: the subsidy for the height, to our output's script, then the lock time.
	sprintf(&sub->coinb2[sub2], "%016llx", (unsigned long long)__builtin_bswap64(block_reward(s->height))); // subsidy calc for height
	memcpy(&sub->coinb2[sub2+16], &s->coinbase[0].coinb2[j+16], k-j-16);
	sprintf(&sub->coinb2[sub2 + (k-j)], "00000000");
	
	// prep binary versions
	T_DATUM_STRATUM_COINBASE *const built[2] = { &s->coinbase[0], sub };
	for (int b = 0; b < 2; b++) {
		i = strlen(built[b]->coinb1);
		built[b]->coinb1_len = 0;
		for (j = 0; j < i; j += 2) built[b]->coinb1_bin[built[b]->coinb1_len++] = hex2bin_uchar(&built[b]->coinb1[j]);
		i = strlen(built[b]->coinb2);
		built[b]->coinb2_len = 0;
		for (j = 0; j < i; j += 2) built[b]->coinb2_bin[built[b]->coinb2_len++] = hex2bin_uchar(&built[b]->coinb2[j]);
	}
}

void generate_base_coinbase_txns_for_stratum_job(T_DATUM_STRATUM_JOB *s, bool new_block) {
	// The subsidy-only coinbase is built for every job (build_plain_coinbase), not only for
	// new-block jobs: a job of any kind is served as empty work when no coinbase type can carry
	// it safely (see send_mining_notify), and a coinbase that was never built would make blocks
	// no node accepts.
	(void)new_block;
	char cb[512];
	int cb_input_sz = 0;
	bool space_for_en_in_coinbase = false;
	int i, j, k;
	int cb1idx[1] = { 0 };
	int cb2idx[1] = { 0 };
	int target_pot_index;
	
	if (datum_protocol_is_active()) {
		// DATUM
		s->pool_addr_script_len = datum_config.override_mining_pool_scriptsig_len;
		memcpy(&s->pool_addr_script[0], datum_config.override_mining_pool_scriptsig, datum_config.override_mining_pool_scriptsig_len);
		s->is_datum_job = true;
	} else {
		// No pool
		s->pool_addr_script_len = addr_2_output_script(datum_config.mining_pool_address, &s->pool_addr_script[0], 64);
		s->is_datum_job = false;
	}
	if (!s->pool_addr_script_len) {
		DLOG_FATAL("Could not generate output script for pool addr! Perhaps invalid? This is bad.");
		panic_from_thread(__LINE__);
	}
	// copy beginning of the generation txn to the appropriate outputs
	j = strlen(cbstart_hex);
	memcpy(&s->coinbase[0].coinb1[0], cbstart_hex, j);
	cb1idx[0] = j;
	
	cb_input_sz = generate_coinbase_input(s->height, &cb[0], &target_pot_index);
	i = cb_input_sz << 1;
	
	// null terminate... probably not needed
	cb[i] = 0;
	
	if (cb_input_sz <= 85) {
		space_for_en_in_coinbase = true;
	}
	
	if (space_for_en_in_coinbase) {
		cb1idx[0] += append_bitcoin_varint_hex(cb_input_sz+15, &s->coinbase[0].coinb1[cb1idx[0]]); // 15 bytes for extranonce+uid push + data
	} else {
		cb1idx[0] += append_bitcoin_varint_hex(cb_input_sz, &s->coinbase[0].coinb1[cb1idx[0]]);
	}
	memcpy(&s->coinbase[0].coinb1[cb1idx[0]], &cb[0], cb_input_sz*2);
	s->target_pot_index = target_pot_index + (cb1idx[0]>>1); // adjust for placement in the txn. always safe for all types, since the varint will always be 1 byte.
	cb1idx[0] += cb_input_sz*2;
	
	if (space_for_en_in_coinbase) {
		// if we are doing extranonce in the coinbase, then this is ALMOST the end of coinbase1
		// we need a PUSH 14 and our enprefix in the coinbase
		uchar_to_hex(&s->coinbase[0].coinb1[cb1idx[0]], 0x0E);
		cb1idx[0]+=2;
		// TODO: Profile a faster way to do this
		cb1idx[0] += sprintf(&s->coinbase[0].coinb1[cb1idx[0]], "%04" PRIx16, s->enprefix);
	} else {
		// if we are not, then we need to append the "sequence"
		pk_u64le(s->coinbase[0].coinb1, cb1idx[0], 0x6666666666666666ULL);  // "ffffffff"
		cb1idx[0] += 8;
	}
	
	s->coinbase[0].coinb1[cb1idx[0]] = 0;
	
	build_plain_coinbase(s, space_for_en_in_coinbase, cb_input_sz, cb1idx, cb2idx);
}

void generate_coinbase_txns_for_stratum_job(T_DATUM_STRATUM_JOB *s, bool empty_only) {
	// Settled here because this is where every coinbase type is rebuilt, which
	// is after the coinbaser has landed and the commitment set is whatever it
	// is going to be for this job.
	//
	// Each coinbase type says for itself whether it carries the accepts.
	datum_job_note_bmm_accept(s);
	// Account for available vsize, sigops, size, weight, etc
	
	// Note:
	// With a minimum payout of 10 TBC, the largest likely coinbase as of height 840000 is around 16 KB if we paid every miner the minimum to a long address type.
	// This seems highly unlikely.  16KB is more than sufficient.
	
	int i, j, k;
	char cb[300];
	int target_pot_index;
	int cb_input_sz = 0;
	
	bool space_for_en_in_coinbase = false;
	
	int cb1idx[MAX_COINBASE_TYPES] = { 0,0,0,0,0,0 };
	int cb2idx[MAX_COINBASE_TYPES] = { 0,0,0,0,0,0 };
	
	int cb_req_sz[MAX_COINBASE_TYPES] = { 0,0,0,0,0 };
	
	////////////////
	
	// Initial mainnet coinbaser
	if (datum_protocol_is_active()) {
		// DATUM
		s->pool_addr_script_len = datum_config.override_mining_pool_scriptsig_len;
		memcpy(&s->pool_addr_script[0], datum_config.override_mining_pool_scriptsig, datum_config.override_mining_pool_scriptsig_len);
		s->is_datum_job = true;
		// No payouts from the pool (it did not answer, or the value is below
		// what it pays out): the plain coinbase pays the pool's address. With
		// commitments, the sized types are built all the same -- paying the
		// pool's address, and carrying them -- as in solo mode; a copy of the
		// plain coinbase would leave the template's BMM accepts and votes out.
		empty_only = (s->available_coinbase_outputs_count == 0 && s->commitments_count == 0);
	} else {
		// No pool
		s->pool_addr_script_len = addr_2_output_script(datum_config.mining_pool_address, &s->pool_addr_script[0], 64);
		s->is_datum_job = false;
		// Solo, the plain coinbase pays everything to our address, so every
		// type can be a copy of it -- unless the template brought commitments.
		// The plain coinbase has no room for them, and a copy of it would
		// leave a BMM accept out of a block that carries its bid. Build the
		// sized types then: with no payouts, they pay our address and carry
		// the commitments.
		empty_only = (s->commitments_count == 0);
	}
	if (!s->pool_addr_script_len) {
		DLOG_FATAL("Could not generate output script for pool addr! Perhaps invalid? This is bad.");
		panic_from_thread(__LINE__);
	}
	
	// copy beginning of the generation txn to the appropriate outputs
	j = strlen(cbstart_hex);
	for(i=0;i<MAX_COINBASE_TYPES;i++) {
		memcpy(&s->coinbase[i].coinb1[0], cbstart_hex, j);
		cb1idx[i] = j;
	}
	
	cb_input_sz = generate_coinbase_input(s->height, &cb[0], &target_pot_index);
	s->target_pot_index = target_pot_index;
	i = cb_input_sz << 1;
	
	// null terminate... probably not needed
	cb[i] = 0;
	
	// do we have space in the coinbase for the extranonce for types that can do it this way?
	// we need 1 byte for the push, 2 for the enprefix, 4 for en1 and 8 for en2 = 15 bytes
	// coinbase max is 100
	if (cb_input_sz <= 85) {
		space_for_en_in_coinbase = true;
	}
	
	// multiple coinbase options
	// 0 = "empty" --- just pays pool addr, and possibly TIDES data.  extranonce in coinbase if fits, or in first output if not.
	// 1 = "nicehash" --- roughly 500 bytes total... smaller than antminer... has nothing before the extranonce OP_RETURN (or no extranonce OP_RETURN if enough space in the coinbase)
	// 2 = "antminer" --- roughly 730 bytes max size, using a larger coinb1 and UART sync bits.  This also works as a good default.
	// 3 = "whatsminer" --- max 6500 bytes tested.  does not need the extranonce OP_RETURN unless there's no space in the coinbase itself after tags
	// 4 = "huge" --- max 16kB --- this is probably the most we should reasonably attempt to do in the coinbase... something like 380 to 530 outputs, depending on the type of output
	// 5 = "antminer2" --- max 2250 bytes --- latest S21s appear to support this
	
	// only type 2 *needs* the OP_RETURN extranonce, unless the coinbase itself is too long
	// set the len, and copy over the rest of the coinbase
	for(i=0;i<MAX_COINBASE_TYPES;i++) {
		if ((i!=2) && (space_for_en_in_coinbase)) {
			cb1idx[i] += append_bitcoin_varint_hex(cb_input_sz+15, &s->coinbase[i].coinb1[cb1idx[i]]);
		} else {
			cb1idx[i] += append_bitcoin_varint_hex(cb_input_sz, &s->coinbase[i].coinb1[cb1idx[i]]);
		}
		memcpy(&s->coinbase[i].coinb1[cb1idx[i]], &cb[0], cb_input_sz*2);
		// save this and adjust for placement in the txn... this is always safe because the coinbase input is always < 0xFD len
		// little silly to set this multiple times, but it's fine for consistency.
		s->target_pot_index = target_pot_index + (cb1idx[i]>>1);
		cb1idx[i] += cb_input_sz*2;
		
		if ((i!=2) && (space_for_en_in_coinbase)) {
			// if we are doing extranonce in the coinbase, then this is ALMOST the end of coinbase1
			// we need a PUSH 14 and our enprefix in the coinbase
			uchar_to_hex(&s->coinbase[i].coinb1[cb1idx[i]], 0x0E);
			cb1idx[i]+=2;
			// TODO: Profile a faster way to do this
			cb1idx[i] += sprintf(&s->coinbase[i].coinb1[cb1idx[i]], "%04" PRIx16, s->enprefix);
		} else {
			// if we are not, then we need to append the "sequence"
			pk_u64le(s->coinbase[i].coinb1, cb1idx[i], 0x6666666666666666ULL);  // "ffffffff"
			cb1idx[i] += 8;
		}
		
		s->coinbase[i].coinb1[cb1idx[i]] = 0;
	}
	
	// extranonce ends up at the end of coinb1
	// for the antminer hack coinbaser, we want to cram an output or two in coinb1, which is tricky
	// would be much easier to just always use the OP_RETURN, but that's wasteful when not needed as it wastes 10 bytes (wastes 8 bytes for the value, 2 for the OP_RETURN and the PUSH...)
	// if extranonce in the coinbase, then we start coinb2 with the "sequence"
	// if extranonce not in the coinbase, then we already tacked the "sequence" on to coinb1 immediately
	
	// we need to know the output count for each type so we can figure out what to stuff in each one
	// this may be a bit wasteful, but needs to be done.  only needs to happen once per work update, and only when doing non-empty.
	
	build_plain_coinbase(s, space_for_en_in_coinbase, cb_input_sz, cb1idx, cb2idx);
	
	if (empty_only) {
		// copy empty coinbaser to the others
		for (i=1;i<MAX_COINBASE_TYPES;i++) {
			strcpy(s->coinbase[i].coinb1, s->coinbase[0].coinb1);
			strcpy(s->coinbase[i].coinb2, s->coinbase[0].coinb2);
			s->coinbase[i].carries_accepts = s->coinbase[0].carries_accepts;
		}
	} else {
		// ok, let's figure out how much space, if any, we have for miner payout outputs
		// we first need to figure out how much space we are using for each type after required data, so let's do that
		
		// witness output = 46 bytes
		// pool output = pool_addr_script_len + 9
		// coinbase itself = cb_input_sz
		// coinbase len = 1
		// cbstart = 41 bytes
		// lock time = 4 bytes
		// "sequence" = 4 bytes
		// extranonce size = 15 bytes (w/len push needed for either coinbase or OP_RETURN formats)
		// output count... could technically be up to three bytes for types 3 + 4, most likely 1 byte for 0,1,2.
		//     --- lets give ourselves the wiggle room and say 3 bytes
		//
		// total static bytes = 46+9+1+41+4+3+4+15 = 123 bytes
		// not-static bytes = pool_addr_script_len + cb_input_sz + (space_for_en_in_coinbase?0:10)
		//     --- it costs 10 extra bytes to do the OP_RETURN based extranonce
		
		if (!space_for_en_in_coinbase) {
			cb_req_sz[1] = cb_req_sz[2] = cb_req_sz[3] = cb_req_sz[4] = cb_req_sz[5] = 119 + s->pool_addr_script_len + cb_input_sz + 10;
		} else {
			cb_req_sz[1] = cb_req_sz[2] = cb_req_sz[3] = cb_req_sz[4] = cb_req_sz[5] = 119 + s->pool_addr_script_len + cb_input_sz;
			cb_req_sz[2] += 10; // always OP_RETURN extranonce for type 2
		}
		
		// TYPE 1 - "Nicehash" friendly, max 500 bytes
		i = datum_stratum_coinbase_fit_to_template(500, cb_req_sz[1], s);
		generate_coinbase_txns_for_stratum_job_subtypebysize(s, 1, i, space_for_en_in_coinbase, cb1idx, cb2idx, false);
		
		// TYPE 3 - "Whatsminer" friendly, max 6500 bytes
		i = datum_stratum_coinbase_fit_to_template(6500, cb_req_sz[3], s);
		generate_coinbase_txns_for_stratum_job_subtypebysize(s, 3, i, space_for_en_in_coinbase, cb1idx, cb2idx, false);
		
		// TYPE 4 - "YUGE", max 16KB
		i = datum_stratum_coinbase_fit_to_template(16000, cb_req_sz[4], s);
		generate_coinbase_txns_for_stratum_job_subtypebysize(s, 4, i, space_for_en_in_coinbase, cb1idx, cb2idx, false);
		
		// TYPE 5 - "Antminer 2", max 2250 bytes
		i = datum_stratum_coinbase_fit_to_template(2250, cb_req_sz[5], s);
		generate_coinbase_txns_for_stratum_job_subtypebysize(s, 5, i, space_for_en_in_coinbase, cb1idx, cb2idx, false);
		
		// TYPE 2 - Older Antminer stock (S19)
		i = datum_stratum_coinbase_fit_to_template(755, cb_req_sz[2], s);
		generate_coinbase_txns_for_stratum_job_subtypebysize(s, 2, i, false, cb1idx, cb2idx, true);
	}
	
	// prep binary versions of the coinbase for speeding up later
	for(k=0;k<MAX_COINBASE_TYPES;k++) {
		i = strlen(s->coinbase[k].coinb1);
		s->coinbase[k].coinb1_len = 0;
		for(j=0;j<i;j+=2) {
			s->coinbase[k].coinb1_bin[j>>1] = hex2bin_uchar(&s->coinbase[k].coinb1[j]);
			s->coinbase[k].coinb1_len++;
		}
		i = strlen(s->coinbase[k].coinb2);
		s->coinbase[k].coinb2_len = 0;
		for(j=0;j<i;j+=2) {
			s->coinbase[k].coinb2_bin[j>>1] = hex2bin_uchar(&s->coinbase[k].coinb2[j]);
			s->coinbase[k].coinb2_len++;
		}
	}
	
}

// Seed a job's commitments from its template.
//
// Two things can supply commitments and only one can win. The pool sends them
// over DATUM when the gateway takes templates from a plain node -- the pool
// asks the enforcer itself and forwards the bytes. An enforcer template
// carries its own, already chosen alongside the transaction set they belong
// to.
//
// When both are available the template wins, and the pool's are dropped. They
// are the same votes fetched twice, but the template's are the ones coupled to
// this block's transactions: an M7 accept only means anything next to the M8
// requests the enforcer included. Carrying both would put two of each in one
// coinbase.
//
// Returns the number of bytes they will take in the coinbase.
// The 4-byte message tag a commitment carries, past OP_RETURN and its push.
//
// Every BIP300 message is OP_RETURN, one push, then a tag: d6e1c5df for an M2,
// d77d1776 for an M4, and so on. The tag is what makes two commitments the same
// vote rather than two different ones, which is the whole basis for letting one
// replace the other.
// Whether the job's commitment set contains a BMM accept, and therefore
// whether dropping the set changes a valid block into an invalid one.
//
// The request depends on the template alone, so it is settled once, when the
// job is made (datum_job_note_bmm_request), and never cleared again: clearing
// it while the coinbaser rescans let a client served in that moment take the
// full coinbase without the accept. The accept is worked out on the side and
// published with a single store.
void datum_job_note_bmm_request(T_DATUM_STRATUM_JOB *s) {
	bool request = false;
	if (s->block_template) {
		for (uint32_t t = 0; t < s->block_template->txn_count; t++) {
			// Exactly as Chains reads one: see txn_has_bmm_request_output.
			if (txn_has_bmm_request_output(s->block_template->txns[t].txn_data_binary, s->block_template->txns[t].size)) {
				request = true;
				break;
			}
		}
	}
	__atomic_store_n(&s->has_bmm_request, request, __ATOMIC_RELEASE);
}

void datum_job_note_bmm_accept(T_DATUM_STRATUM_JOB *s) {
	unsigned char tag[4];
	bool accept = false;
	for (int i = 0; i < s->commitments_count; i++) {
		if (datum_commitment_tag(s->commitments[i].output_script, s->commitments[i].output_script_len, tag)
		    && tag[0] == 0xd1 && tag[1] == 0x61 && tag[2] == 0x73 && tag[3] == 0x68) {
			accept = true;
			break;
		}
	}
	// An accept of the template that did not fit: the block's accepts are not
	// all there, whatever this job carries.
	if (s->block_template && s->block_template->bmm_accepts_dropped) accept = false;
	__atomic_store_n(&s->has_bmm_accept, accept, __ATOMIC_RELEASE);
}

// Whether a client on this coinbase type may be served this job.
//
// A coinbase that dropped the commitments for want of room is fine when they
// are only votes: not voting is legal. It is not fine when one of them is a
// BMM accept, because the request it answers is a transaction in this job's
// block, and a block carrying the request without the accept is one the
// enforcer rejects while the node and the gateway both call it a success.
// Block 969,898 was lost exactly that way.
bool datum_job_coinbase_is_safe(const T_DATUM_STRATUM_JOB *j, int cbselect) {
	if (!j || cbselect < 0 || cbselect >= MAX_COINBASE_TYPES) return false;
	// A bid in the block and no accept in the job: whatever coinbase is
	// built, the block is invalid on the drivechain. Only empty work is safe.
	const bool request = __atomic_load_n(&j->has_bmm_request, __ATOMIC_ACQUIRE);
	const bool accept = __atomic_load_n(&j->has_bmm_accept, __ATOMIC_ACQUIRE);
	if (request && !accept) return false;
	if (!accept) return true;
	return j->coinbase[cbselect].carries_accepts;
}

// OP_RETURN and one push that ends the script: what Chains reads as a message, and nothing that
// counts as a signature operation.
bool datum_script_is_one_push(const unsigned char *script, int len) {
	if (!script || len < 2 || script[0] != 0x6a) return false;
	const unsigned char op = script[1];
	long n, at;
	if (op <= 0x4b) { n = op; at = 2; }
	else if (op == 0x4c) { if (len < 3) return false; n = script[2]; at = 3; }
	else if (op == 0x4d) { if (len < 4) return false; n = script[2] | (script[3] << 8); at = 4; }
	else return false;
	return at + n == len;
}

bool datum_commitment_tag(const unsigned char *script, int len, unsigned char out[4]) {
	if (!script || len < 2 || script[0] != 0x6a) return false;
	int i = 1;
	const unsigned char op = script[i++];
	if (op <= 0x4b) {
		/* length is the opcode */
	} else if (op == 0x4c) {
		i += 1;
	} else if (op == 0x4d) {
		i += 2;
	} else if (op == 0x4e) {
		i += 4;
	} else {
		return false;
	}
	if (i + 4 > len) return false;
	memcpy(out, &script[i], 4);
	return true;
}

// Drop every commitment already held that carries this tag.
//
// Used when the pool sends a message of its own, so the pool's replaces what
// the template brought rather than joining it.
//
// Called once per tag for a whole merge, never once per commitment. A tag is
// not a message: every M2 carries the same one, and a pool acking two
// proposals sends two M2s that differ only in the slot and hash inside them.
// Calling this for each of them in turn had the second delete the first, and
// the pool acked two sidechains in its own interface while every block it
// found carried an ack for one.
void datum_commitments_drop_tag(T_DATUM_STRATUM_JOB *s, const unsigned char tag[4]) {
	int kept = 0;
	for (int i = 0; i < s->commitments_count; i++) {
		const int clen = s->commitments[i].output_script_len;
		unsigned char t[4];
		if (datum_commitment_tag(s->commitments[i].output_script, clen, t) && !memcmp(t, tag, 4)) {
			s->commitments_size -= 8 + (clen < 0xFD ? 1 : 3) + clen;
			continue;
		}
		if (kept != i) s->commitments[kept] = s->commitments[i];
		kept++;
	}
	s->commitments_count = kept;
}

int commitments_from_template(T_DATUM_STRATUM_JOB *s) {
	s->commitments_count = 0;
	s->commitments_size = 0;
	if (!s->block_template || s->block_template->commitments_count <= 0) return 0;

	for (int i = 0; i < s->block_template->commitments_count && i < DATUM_MAX_COMMITMENTS; i++) {
		int clen = s->block_template->commitments[i].output_script_len;
		if (clen < 1 || clen > DATUM_MAX_COMMITMENT_SCRIPT) continue;
		// Written at commitments_count, not at i. Skipping one and still
		// indexing by the loop counter leaves a hole holding whatever the
		// previous job put there, and that hole is emitted as a commitment.
		memcpy(s->commitments[s->commitments_count].output_script, s->block_template->commitments[i].output_script, clen);
		s->commitments[s->commitments_count].output_script_len = clen;
		// 8 bytes of value, the script's own length prefix, then the script.
		s->commitments_size += 8 + (clen < 0xFD ? 1 : 3) + clen;
		s->commitments_count++;
	}
	if (s->commitments_count) {
		DLOG_DEBUG("Template carries %d commitment(s), %d bytes", s->commitments_count, s->commitments_size);
	}
	return s->commitments_size;
}

// How many sidechains an M4's upvote vector votes for, or -1 if it does not
// carry one.
//
// The M4 body is a version byte then, for the explicit forms, one entry per
// active sidechain: 0x01 for one-byte entries, 0x02 for two-byte. 0x00 (repeat
// previous) and 0x03 (back the leader) carry no vector at all.
int datum_m4_entry_count(const unsigned char *script, int len) {
	unsigned char tag[4];
	if (!datum_commitment_tag(script, len, tag)) return -1;
	if (!(tag[0] == 0xd7 && tag[1] == 0x7d && tag[2] == 0x17 && tag[3] == 0x76)) return -1;
	// Body starts after OP_RETURN, the push opcode (and its length bytes) and
	// the tag. Only the short push forms appear here; an M4 is never large.
	int i = 1;
	const unsigned char op = script[i++];
	if (op == 0x4c) i += 1;
	else if (op == 0x4d) i += 2;
	else if (op == 0x4e) i += 4;
	else if (op > 0x4b) return -1;
	i += 4; // the tag
	if (i >= len) return -1;
	const unsigned char version = script[i++];
	const int body = len - i;
	if (version == 0x01) return body;
	if (version == 0x02) return body / 2;
	return -1; // repeat-previous or leading-by-50: no vector to compare
}

// Whether a vote (M4) fits the block it would go in, by what the node said of
// the sidechains in getblocktemplate (drivechain_votable): one entry per active
// sidechain, each abstaining, downvoting, or naming a bundle that is pending.
// A vote that does not fit makes the block invalid. A node that does not say
// (an enforcer, as on eCash) leaves the check to the one against the
// template's own M4, in datum_coinbaser_v2_parse. Not an M4: nothing to check.
bool datum_m4_fits_template(const unsigned char *script, int len, const T_DATUM_TEMPLATE_DATA *t) {
	unsigned char tag[4];
	if (!datum_commitment_tag(script, len, tag)) return true;
	if (!(tag[0] == 0xd7 && tag[1] == 0x7d && tag[2] == 0x17 && tag[3] == 0x76)) return true;
	if (!t || !t->votable_known) return true;
	int i = 1;
	const unsigned char op = script[i++];
	if (op == 0x4c) i += 1;
	else if (op == 0x4d) i += 2;
	else if (op == 0x4e) i += 4;
	else if (op > 0x4b) return false;
	i += 4; // the tag
	if (i >= len) return false;
	const unsigned char version = script[i++];
	const int body = len - i;
	if (version == 0x00 || version == 0x03) return body == 0; // repeat the last votes, or follow the leader
	if (version == 0x01) {
		if (body != t->votable_count) return false;
		for (int v = 0; v < body; v++) {
			const unsigned char e = script[i + v];
			if (e != 0xFF && e != 0xFE && e >= t->votable_bundles[v]) return false;
		}
		return true;
	}
	if (version == 0x02) {
		if (body % 2 || body / 2 != t->votable_count) return false;
		bool needed = false;
		for (int v = 0; v < body / 2; v++) {
			const unsigned int e = (unsigned int)script[i + 2*v] | ((unsigned int)script[i + 2*v + 1] << 8);
			if (e != 0xFFFF && e != 0xFFFE && e >= t->votable_bundles[v]) return false;
			// The two byte form only where an entry does not fit in one.
			if (e > 0xFD && e != 0xFFFF && e != 0xFFFE) needed = true;
		}
		return needed;
	}
	return false;
}

int datum_coinbaser_v2_parse(T_DATUM_STRATUM_JOB *s, unsigned char *coinbaser, int cblen, bool must_free) {
	// parse raw outputs from DATUM connection into a useful coinbaser
	uint64_t outval = 0;
	uint64_t tally = 0;
	int cidx = 0;
	int slen = 0;
	int cbvalid = 0;
	int datum_id;
	
	if (!coinbaser) {
		DLOG_WARN("Coinbaser is NULL Using default/empty");
		s->available_coinbase_outputs_count = 0;
		commitments_from_template(s);
		return 0;
	}
	
	if (cblen < 9) {
		// 0 outputs possible
		DLOG_WARN("Coinbaser length is invalid (too short). Using default/empty");
		s->available_coinbase_outputs_count = 0;
		commitments_from_template(s);
		if (must_free) free(coinbaser);
		return 0;
	}
	
	DLOG_DEBUG("Coinbaser v2 size %d", cblen);
	
	datum_id = coinbaser[cidx]; cidx++;
	
	// v3: the pool set the high bit of the datum id to say a commitment
	// section leads the payload. The pool only does this for a gateway that
	// declared support in its user agent, so an unmodified gateway never sees
	// it and never has to recognise it.
	//
	//   [1 byte count]
	//   count x ( [2 bytes script length LE] [script] )
	//
	// Two-byte lengths because a payout's one byte caps at 255 and a wide M4
	// bundle vote runs past 500.
	bool from_template = commitments_from_template(s) > 0;
	// How many BMM accepts this template brought of its own.
	//
	// A gateway whose node runs an enforcer gets its accepts in the template,
	// chosen against the very transaction set it is about to mine. Nothing the
	// pool can send improves on that, and the pool's were chosen against a
	// different node's mempool, so letting them replace these would swap a
	// certainty for a guess. Counted before the merge, because the merge is
	// what appends the pool's to the same array.
	int template_bmm_accepts = 0;
	for (int q = 0; q < s->commitments_count; q++) {
		unsigned char t[4];
		if (datum_commitment_tag(s->commitments[q].output_script,
		                         s->commitments[q].output_script_len, t)
		    && t[0] == 0xd1 && t[1] == 0x61 && t[2] == 0x73 && t[3] == 0x68) {
			template_bmm_accepts++;
		}
	}
	if (datum_id & 0x80) {
		datum_id &= 0x7F;
		if (cidx >= cblen) {
			DLOG_ERROR("Coinbaser claims commitments but ends before the count. Using default/empty");
			goto fail;
		}
		int ccount = coinbaser[cidx]; cidx++;
		if (ccount > DATUM_MAX_COMMITMENTS) {
			// Refusing beats truncating: a dropped commitment is a vote that
			// silently did not happen, and mining without it looks identical
			// to mining with it.
			DLOG_ERROR("Coinbaser has %d commitments, max %d. Using default/empty", ccount, DATUM_MAX_COMMITMENTS);
			goto fail;
		}
		// The tags whose template commitments this merge has already cleared.
		// See datum_commitments_drop_tag: clearing is per tag, not per message.
		unsigned char cleared[DATUM_MAX_COMMITMENTS][4];
		int cleared_count = 0;
		bool pool_m4 = false;
		// The kinds (tag and slot) of the pool's messages taken so far.
		unsigned char pool_kinds[DATUM_MAX_COMMITMENTS][5];
		int pool_kinds_count = 0;
		for (int ci = 0; ci < ccount; ci++) {
			if (cidx + 2 > cblen) {
				DLOG_ERROR("Coinbaser commitment %d has no length. Using default/empty", ci);
				goto fail;
			}
			int clen = (int)coinbaser[cidx] | ((int)coinbaser[cidx+1] << 8); cidx += 2;
			if (clen < 1 || clen > DATUM_MAX_COMMITMENT_SCRIPT || cidx + clen > cblen) {
				DLOG_ERROR("Coinbaser commitment %d length (%d) is invalid. Using default/empty", ci, clen);
				goto fail;
			}
			const unsigned char *cscript = &coinbaser[cidx]; cidx += clen;
			// The pool's vote wins over the template's.
			//
			// The pool decides what it votes from its own policy and its own
			// miners' weighted vote; a template's commitments are whatever the
			// node building it happens to think. When both are present the
			// pool's is the decision anyone was actually asked about, so it
			// replaces the template's message of the same kind.
			//
			// Only of the same kind. A template also carries commitments the
			// pool never sends -- an M7 answering a BMM request is the money
			// one -- and dropping the template's whole set to make room for a
			// vote would throw those away with it.
			//
			// One exception, and it is the expensive one. An M4's upvote vector
			// has one entry per active sidechain, and a vector of the wrong
			// length is not a smaller vote -- it is an invalid block. This pool
			// mined one: height 996701, built on a one-entry vector where the
			// chain wanted nine, accepted by our own node and thrown out by
			// every peer. The subsidy, the fees and three BMM accepts went with
			// it.
			//
			// So when the template brought an M4 of its own, the pool's has to
			// agree with it about how many sidechains there are. If it does
			// not, the template's stands. A vote not cast costs one block's
			// worth of influence; a vote cast wrongly costs the block.
			// What Chains takes per block, checked before anything is carried: a block
			// breaking one of these rules is one every node rejects.
			{
				unsigned char tag[4];
				if (!datum_script_is_one_push(cscript, clen)) {
					DLOG_ERROR("Pool sent a commitment that is not OP_RETURN and one push. Dropping it.");
					continue;
				}
				if (datum_commitment_tag(cscript, clen, tag)) {
					const bool is_m4 = tag[0] == 0xd7 && tag[1] == 0x7d && tag[2] == 0x17 && tag[3] == 0x76;
					const bool per_slot = (tag[0] == 0xd6 && tag[1] == 0xe1 && tag[2] == 0xc5 && tag[3] == 0xdf)  // M2
					                   || (tag[0] == 0xd4 && tag[1] == 0x5a && tag[2] == 0xa9 && tag[3] == 0x43)  // M3
					                   || (tag[0] == 0xd1 && tag[1] == 0x61 && tag[2] == 0x73 && tag[3] == 0x68); // M7
					if (is_m4 && pool_m4) {
						DLOG_ERROR("Pool sent a second M4. Dropping it: a block has one.");
						continue;
					}
					if (per_slot && clen > 6) {
						// Among the pool's own: the template's of the same kind are cleared below,
						// when the pool's replace them.
						bool duplicate = false;
						for (int q = 0; q < pool_kinds_count && !duplicate; q++) {
							duplicate = !memcmp(pool_kinds[q], tag, 4) && pool_kinds[q][4] == cscript[6];
						}
						if (duplicate) {
							DLOG_ERROR("Pool sent a second commitment of one kind for sidechain %d. Dropping it: a block has one.", cscript[6]);
							continue;
						}
					}
					if (tag[0] == 0xd1 && tag[1] == 0x61 && tag[2] == 0x73 && tag[3] == 0x68 &&
					    !datum_bmm_accept_answers_a_request(cscript, clen, s->block_template ? s->block_template->txns : NULL,
					                                        s->block_template ? s->block_template->txn_count : 0)) {
						DLOG_ERROR("Pool sent a BMM accept with no request in our block for that sidechain and block. Dropping it.");
						continue;
					}
					if (is_m4) pool_m4 = true;
				}
			}
			{
				unsigned char tag[4];
				if (datum_commitment_tag(cscript, clen, tag)
				    && tag[0] == 0xd1 && tag[1] == 0x61 && tag[2] == 0x73 && tag[3] == 0x68
				    && template_bmm_accepts > 0) {
					// This gateway has an enforcer and has already been given
					// the accepts that match its own block. The pool's are for
					// somebody else's transaction set; taking them would drop
					// these, because the merge below replaces by tag and every
					// accept shares one.
					DLOG_DEBUG("Ignoring a pool-sent BMM accept: this template carries %d of its own.",
					           template_bmm_accepts);
					continue;
				}
				if (datum_commitment_tag(cscript, clen, tag)) {
					int mine = datum_m4_entry_count(cscript, clen);
					int theirs = -1;
					if (mine >= 0) {
						for (int q = 0; q < s->commitments_count; q++) {
							int n = datum_m4_entry_count(s->commitments[q].output_script,
							                             s->commitments[q].output_script_len);
							if (n >= 0) { theirs = n; break; }
						}
					}
					if (!datum_m4_fits_template(cscript, clen, s->block_template)) {
						DLOG_ERROR("Pool sent an M4 that does not fit this template's sidechains and bundles. "
						           "Not carrying it: a vote that does not fit is an invalid block.");
						continue;
					}
					if (mine >= 0 && theirs >= 0 && mine != theirs) {
						DLOG_ERROR("Pool sent an M4 voting for %d sidechains where this template has %d. "
						           "Keeping the template's: a vector of the wrong length is an invalid "
						           "block, not a smaller vote.", mine, theirs);
						continue;
					}
					bool cleared_already = false;
					for (int q = 0; q < cleared_count; q++) {
						if (!memcmp(cleared[q], tag, 4)) { cleared_already = true; break; }
					}
					if (!cleared_already) {
						datum_commitments_drop_tag(s, tag);
						if (cleared_count < DATUM_MAX_COMMITMENTS) {
							memcpy(cleared[cleared_count++], tag, 4);
						}
					}
				}
			}
			// Template commitments are already in the array, so the pool's now
			// append to them rather than starting from empty. Bounded here for
			// the first time because of it.
			if (s->commitments_count >= DATUM_MAX_COMMITMENTS) {
				DLOG_ERROR("No room for the pool's commitment beside the template's. Dropping it.");
				continue;
			}

			// The same rule the template parser applies, applied here too.
			//
			// A commitment the pool sends has not been near that parser, and a
			// BMM accept is only valid beside the M8 request it answers. The
			// pool decides its commitments against its own node's transaction
			// set; a gateway building templates from a different node has a
			// different set, so an accept that was backed there may be
			// unbacked here. The result is a block this node accepts, builds
			// on, and reports nothing wrong about, while the enforcer rejects
			// it and everything after it is orphaned.
			//
			// The pool sends only sidechain and bundle votes today, which
			// commit to no transaction and always pass -- so this changes
			// nothing now and is the check that has to already be here on the
			// day that stops being true.
			//
			// Dropped rather than failing the whole coinbaser: refusing that
			// would take the payout list with it, and one vote not cast is a
			// far smaller loss than a block that pays nobody correctly.
			if (!datum_template_commitment_is_backed(cscript, clen,
			        s->block_template ? s->block_template->txns : NULL,
			        s->block_template ? s->block_template->txn_count : 0)) {
				DLOG_ERROR("Pool sent a BMM accept whose request is not in our block. Dropping it: "
				           "carrying it would build a block our node accepts and the enforcer rejects.");
				continue;
			}
			memcpy(s->commitments[s->commitments_count].output_script, cscript, clen);
			s->commitments[s->commitments_count].output_script_len = clen;
			{
				unsigned char kind[4];
				if (clen > 6 && pool_kinds_count < DATUM_MAX_COMMITMENTS && datum_commitment_tag(cscript, clen, kind)) {
					memcpy(pool_kinds[pool_kinds_count], kind, 4);
					pool_kinds[pool_kinds_count][4] = cscript[6];
					pool_kinds_count++;
				}
			}
			// 8 bytes of value + the script's own length prefix + the script.
			// Scripts past 0x4B need a longer prefix; commitments routinely
			// are, so this is counted rather than assumed to be one byte.
			s->commitments_size += 8 + (clen < 0xFD ? 1 : 3) + clen;
			s->commitments_count++;
		}
		if (from_template && ccount) {
			DLOG_DEBUG("Coinbaser carries %d commitment(s), %d bytes: %d from the pool, replacing "
			           "the template's votes of the same kind and keeping the rest",
			           s->commitments_count, s->commitments_size, ccount);
		} else {
			DLOG_DEBUG("Coinbaser carries %d commitment(s), %d bytes", s->commitments_count, s->commitments_size);
		}
	}
	
	while (cidx < cblen) {
		if (cidx + 8 + 1 > cblen) {
			DLOG_ERROR("Coinbaser length is invalid (mid-parsing). Using default/empty");
			goto fail;
		}
		outval = upk_u64le(coinbaser, cidx); cidx+=8;
		if ((outval + tally) > s->coinbase_value) {
			// we can't include this value, since it would put us over our total available!
			// this shouldn't happen, however...
			break;
		}
		slen = coinbaser[cidx]; cidx++;
		if (slen < 2 || slen > 64 || cidx + slen > cblen) {
			DLOG_ERROR("Script length (%d) is invalid. Using default/empty", slen);
			goto fail;
		}
		
		tally += outval;
		memcpy(s->available_coinbase_outputs[cbvalid].output_script, &coinbaser[cidx], slen); cidx+=slen;
		// 64-bit value in sats is part of the output
		s->available_coinbase_outputs[cbvalid].value_sats = outval;
		if (s->available_coinbase_outputs[cbvalid].output_script[0] == 0x76) { // kludge for checking for P2PKH output
			s->available_coinbase_outputs[cbvalid].sigops = 4;
		} else {
			s->available_coinbase_outputs[cbvalid].sigops = 0;
		}
		
		s->available_coinbase_outputs[cbvalid].output_script_len = slen;
		
		cbvalid++;
		
		if (cbvalid >= 512) break; // limitation of datum for now
	}
	
	s->datum_coinbaser_id = datum_id;
	s->available_coinbase_outputs_count = cbvalid;
	if (must_free) free(coinbaser);
	return cbvalid;

	// Every malformed-coinbaser path lands here. Returning straight from the
	// middle of the parse used to leak the buffer the caller handed us, once
	// per bad coinbaser.
fail:
	s->available_coinbase_outputs_count = 0;
	// The pool's commitments may be half merged by now, with template votes of their kind already
	// dropped: back to the template's own, whole, as if the pool had sent nothing.
	commitments_from_template(s);
	if (must_free) free(coinbaser);
	return 0;
}

void *datum_coinbaser_thread(void *ptr) {
	int sjob = -1;
	T_DATUM_STRATUM_JOB *s = NULL;
	bool need_coinbaser = false;
	int i;
	
	DLOG_DEBUG("Coinbaser thread active");
	
	while(1) {
		// check if we need to fetch any new coinbasers
		// check if the stratum job has been updated
		pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
		if (global_latest_stratum_job_index != sjob) {
			s = global_cur_stratum_jobs[global_latest_stratum_job_index];
			if (s) {
				sjob = global_latest_stratum_job_index;
				if (s->need_coinbaser) {
					need_coinbaser = true;
				}
			} else {
				need_coinbaser = false;
			}
		}
		pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
		
		if (need_coinbaser) {
			// fetch remote coinbaser for job
			DLOG_DEBUG("Job %d needs a coinbaser!", sjob);
			if (datum_protocol_is_active()) {
				// The template's own commitments, whatever comes of the fetch:
				// it gives up on several paths (a timeout, a lost connection, a
				// value it does not pay out) without parsing anything.
				commitments_from_template(s);
				i = datum_protocol_coinbaser_fetch(s);
			} else {
				// No pool: nothing to pay but our own address. The template's
				// commitments still have to go in -- a node that serves a
				// coinbasetxn (an enforcer, or a Chains node) left its BMM bids
				// in the block, and each needs the accept the template carries.
				// Without this, solo blocks kept the bid and lost the accept.
				s->available_coinbase_outputs_count = 0;
				commitments_from_template(s);
				i = 0;
			}
			if (i>=0) {
				DLOG_DEBUG("Generating coinbases for up to %d outputs", i);
				generate_coinbase_txns_for_stratum_job(s, false);
				if (need_coinbaser_rwlocks_init_done) {
					pthread_rwlock_wrlock(&need_coinbaser_rwlocks[sjob]);
					s->need_coinbaser = false;
					pthread_rwlock_unlock(&need_coinbaser_rwlocks[sjob]);
					need_coinbaser = false;
				}
				DLOG_DEBUG("Generated and notified.");
			}
		}
		
		usleep(12000);
	}
}

int datum_coinbaser_init(void) {
	pthread_t pthread_datum_coinbaser_thread;
	int result = pthread_create(&pthread_datum_coinbaser_thread, NULL, datum_coinbaser_thread, NULL);

	if (result != 0) {
		DLOG_FATAL("datum_coinbaser_init: pthread_create failed with code %d", result);
		return -1;
	}

	return 0;
}
