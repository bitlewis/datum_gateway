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
 * Copyright (c) 2025 Bitcoin Ocean, LLC & Luke Dashjr
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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "datum_jsonrpc.h"
#include "datum_stratum.h"
#include "datum_conf.h"
#include "datum_utils.h"
#include "datum_submitblock.h"

void datum_stratum_mod_username_tests() {
	const char * const s_umods = "{\"x\":{\"addrA\": 0.3}, \"abc\":{\"addrB\":0.3,\"addrC\":0.3},\":)\":{\"\":0.5}}";
	json_error_t err;
	json_t * const j_umods = JSON_LOADS(s_umods, &err);
	datum_test(j_umods);
	struct datum_username_mod *umods = NULL;
	int ret = datum_config_parse_username_mods(&umods, j_umods, false);
	datum_test(ret == 1);
	json_decref(j_umods);
	datum_config.stratum_username_mod = umods;
	
	char buf[0x100];
	char * const pool_addr = datum_config.mining_pool_address;
	char *s, *modname;
	const char *res, *a1, *a2;
	
	strcpy(pool_addr, "dummy");
	
	s = "def~G";
	modname = &s[4];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 1) == s);
	
	s = "def~x";
	modname = &s[4];
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 1) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 1) == pool_addr);
	
	s = "def~abc";
	modname = &s[4];
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 3);
	if (0 == strcmp(res, "addrB")) {  // jansson doesn't order keys'
		a1 = "addrB";
		a2 = "addrC";
	} else {
		a1 = "addrC";
		a2 = "addrB";
	}
	datum_test(0 == strcmp(res, a1));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 3);
	datum_test(0 == strcmp(res, a1));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 3);
	datum_test(0 == strcmp(res, a2));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x9999, modname, 3);
	datum_test(0 == strcmp(res, a2));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x999a, modname, 3) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 3) == pool_addr);
	
	s = "def.ghi~abc";
	modname = &s[8];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a1, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a1, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a2, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x9999, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a2, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x999a, modname, 3) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 3) == pool_addr);
	
	s = "def.ghi~:)";
	modname = &s[8];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 2) == buf);
	datum_test(0 == strcmp(buf, "def.ghi"));
	memset(buf, 0, 7);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x7fff, modname, 2) == buf);
	datum_test(0 == strcmp(buf, "def.ghi"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x8000, modname, 2) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 2) == pool_addr);
	
	// Intentionally overflow buf with address: we lose the worker name, but get the full address via its umod buffer
	s = "def.ghi~x";
	modname = &s[8];
	memset(buf, 0x0e, 8);
	res = datum_stratum_mod_username(s, buf, 2, 0, modname, 1);
	datum_test(res != buf);
	datum_test(res != pool_addr);
	datum_test(buf[2] == 0x0e);
	datum_test(0 == strcmp(res, "addrA"));
	res = datum_stratum_mod_username(s, buf, 2, 0x4ccc, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	datum_test(datum_stratum_mod_username(s, buf, 2, 0x4ccd, modname, 1) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, 2, 0xffff, modname, 1) == pool_addr);
	datum_test(buf[2] == 0x0e);
	datum_test(buf[6] == 0x0e);
	res = datum_stratum_mod_username(s, buf, 6, 0, modname, 1);
	datum_test(res == buf);
	datum_test(res != pool_addr);
	datum_test(buf[6] == 0x0e);
	datum_test(0 == strcmp(res, "addrA"));
	memset(buf, 0x0e, 9);
	datum_test(datum_stratum_mod_username(s, buf, 7, 0, modname, 1) == buf);
	datum_test(buf[8] == 0x0e);
	datum_test(0 == strcmp(res, "addrA."));
	memset(buf, 0x0e, 10);
	datum_test(datum_stratum_mod_username(s, buf, 8, 0, modname, 1) == buf);
	datum_test(buf[9] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.g"));
	memset(buf, 0x0e, 11);
	datum_test(datum_stratum_mod_username(s, buf, 9, 0, modname, 1) == buf);
	datum_test(buf[10] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.gh"));
	memset(buf, 0x0e, 12);
	datum_test(datum_stratum_mod_username(s, buf, 10, 0, modname, 1) == buf);
	datum_test(buf[11] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.ghi"));
	s = "def.ghi~:)";
	modname = &s[8];
	memset(buf, 0x0e, 9);
	datum_test(datum_stratum_mod_username(s, buf, 2, 0, modname, 2) == buf);
	datum_test(buf[2] == 0x0e);
	datum_test(0 == strcmp(res, "d"));
	datum_test(datum_stratum_mod_username(s, buf, 6, 0, modname, 2) == buf);
	datum_test(buf[6] == 0x0e);
	datum_test(0 == strcmp(res, "def.g"));
	datum_test(datum_stratum_mod_username(s, buf, 7, 0, modname, 2) == buf);
	datum_test(buf[7] == 0x0e);
	datum_test(0 == strcmp(res, "def.gh"));
	datum_test(datum_stratum_mod_username(s, buf, 8, 0, modname, 2) == buf);
	datum_test(buf[8] == 0x0e);
	datum_test(0 == strcmp(res, "def.ghi"));
}

static void coinbase_types_by_name_and_rule(void) {
	datum_test(datum_stratum_coinbase_type_by_name("antmain2") == 5);
	datum_test(datum_stratum_coinbase_type_by_name("Respect") == 3);
	datum_test(datum_stratum_coinbase_type_by_name("3") == 3);
	datum_test(datum_stratum_coinbase_type_by_name("blank") == -1); // not a type a miner may pick
	datum_test(datum_stratum_coinbase_type_by_name("9") == -1);
	datum_test(datum_stratum_coinbase_type_by_name("") == -1);
	
	memset(datum_config.stratum_v1_coinbase_types, 0, sizeof(datum_config.stratum_v1_coinbase_types));
	strcpy(datum_config.stratum_v1_coinbase_types[0], "NerdQAxe=antmain2");
	strcpy(datum_config.stratum_v1_coinbase_types[1], "broken rule");
	strcpy(datum_config.stratum_v1_coinbase_types[2], "*bosminer=respect");
	strcpy(datum_config.stratum_v1_coinbase_types[3], "Antminer S19=nosuch");
	datum_test(datum_stratum_coinbase_type_from_rules("NerdQAxe TPS546/BM1370/v1.1.0") == 5);
	datum_test(datum_stratum_coinbase_type_from_rules("bosminer-plus-tuner 2.0") == 3);
	datum_test(datum_stratum_coinbase_type_from_rules("Antminer S19/1.0") == -1);
	datum_test(datum_stratum_coinbase_type_from_rules("whatsminer/v1") == -1);
	datum_test(datum_stratum_coinbase_type_from_rules("") == -1);
	memset(datum_config.stratum_v1_coinbase_types, 0, sizeof(datum_config.stratum_v1_coinbase_types));
	printf("  coinbase types resolve by name, and operator rules match by prefix or substring\n");
}

// A coinbase that dropped the commitments is fine for votes and fatal for a
// BMM accept: the request it answers is a transaction in the same block.
static void a_dropped_bmm_accept_makes_a_coinbase_unservable(void) {
	T_DATUM_STRATUM_JOB j;
	memset(&j, 0, sizeof(j));
	j.commitments_count = 3;

	// Votes only: a type that could not fit them abstains, which is legal.
	j.bmm_accepts = 0;
	j.coinbase[1].accepts = 0;
	j.coinbase[4].accepts = 0;
	datum_test(datum_job_coinbase_is_safe(&j, 1));
	datum_test(datum_job_coinbase_is_safe(&j, 4));

	// Two of them are accepts: only a type that carries both may be served.
	j.bmm_accepts = 2;
	j.coinbase[4].accepts = 2;
	datum_test(!datum_job_coinbase_is_safe(&j, 1));
	datum_test(datum_job_coinbase_is_safe(&j, 4));
	datum_test(!datum_job_coinbase_is_safe(&j, 0));
	datum_test(!datum_job_coinbase_is_safe(&j, MAX_COINBASE_TYPES));
	datum_test(!datum_job_coinbase_is_safe(NULL, 1));
	// An accept merged after a coinbase was built (the pool's, after coinbase
	// 0 was made with the job): that coinbase no longer carries them all.
	j.bmm_accepts = 3;
	datum_test(!datum_job_coinbase_is_safe(&j, 4));
	j.bmm_accepts = 2;

	// A bid in the block with no accept in the job: no coinbase type can save
	// it, not even one with room, so none is served.
	j.bmm_accepts = 0;
	j.has_bmm_request = true;
	for (int cb = 0; cb < MAX_COINBASE_TYPES; cb++) datum_test(!datum_job_coinbase_is_safe(&j, cb));
	// With the accepts loaded, the types that carry them are fine again.
	j.bmm_accepts = 2;
	datum_test(datum_job_coinbase_is_safe(&j, 4));
	datum_test(!datum_job_coinbase_is_safe(&j, 1));
	// Three bids and two accepts: one bid goes unanswered, so nothing is served.
	j.bmm_requests = 3;
	datum_test(!datum_job_coinbase_is_safe(&j, 4));
	j.bmm_requests = 2;
	datum_test(datum_job_coinbase_is_safe(&j, 4));
	printf("  a coinbase that dropped a BMM accept is not served\n");
}

// A job whose coinbase is filler but whose header fields are real enough for
// send_mining_notify, with the network target of bits.
static void fake_job(T_DATUM_STRATUM_JOB *j, int index, uint32_t bits) {
	memset(j, 0, sizeof(*j));
	j->global_index = index;
	strcpy(j->job_id, "6625a3d53cc0e500");
	memset(j->prevhash, '1', 64);
	strcpy(j->version, "20000000");
	snprintf(j->nbits, sizeof(j->nbits), "%08x", bits);
	strcpy(j->ntime, "6625406b");
	strcpy(j->merklebranches_full, "[]");
	j->nbits_uint = bits;
	nbits_to_target(bits, j->block_target);
	j->diff_cap = datum_diff_cap_for_target(j->block_target);
	// coinb1: 40 bytes, the PoT byte at 30; coinb2: 4 bytes.
	memset(j->coinbase[0].coinb1, '0', 80);
	j->coinbase[0].coinb1_len = 40;
	strcpy(j->coinbase[0].coinb2, "00000000");
	j->coinbase[0].coinb2_len = 4;
	memcpy(&j->subsidy_only_coinbase, &j->coinbase[0], sizeof(j->coinbase[0]));
	j->target_pot_index = 30;
}

// The difficulty in the last mining.set_difficulty in the client's buffer, or 0.
static uint64_t last_set_difficulty(const T_DATUM_CLIENT_DATA *c) {
	const char *key = "\"mining.set_difficulty\",\"params\":[";
	const char *p = c->w_buffer, *last = NULL;
	while ((p = strstr(p, key))) { last = p; p++; }
	return last ? strtoull(last + strlen(key), NULL, 10) : 0;
}

// The PoT byte the last mining.notify in the buffer carries in its coinb1.
static int last_pot_byte(const T_DATUM_CLIENT_DATA *c, int target_pot_index) {
	const char *p = c->w_buffer, *last = NULL;
	while ((p = strstr(p, "\"mining.notify\""))) { last = p; p++; }
	if (!last) return -1;
	// job id, prevhash, then coinb1: the fifth quote after "params":[
	const char *q = strstr(last, "\"params\":[");
	if (!q) return -1;
	q += 10;
	for (int n = 0; n < 5; n++) { q = strchr(q, '"'); if (!q) return -1; q++; }
	return hex2bin_uchar(&q[target_pot_index * 2]);
}

// Share difficulty is capped at the job's network difficulty -- a miner
// reports only what meets its share target, so above the network's the blocks
// in between are never seen -- while the pool keeps getting shares at the
// difficulty their PoT byte claims, and nothing below it.
static void the_client_difficulty_never_exceeds_the_networks(void) {
	// The cap from a target.
	unsigned char bt[32], t[32];
	nbits_to_target(0x1d00ffff, bt);
	datum_test(datum_diff_cap_for_target(bt) == 1);           // min-difficulty block
	nbits_to_target(0x207fffff, bt);
	datum_test(datum_diff_cap_for_target(bt) == 1);           // regtest: easier than 1, still 1
	nbits_to_target(0x1c00ffff, bt);
	datum_test(datum_diff_cap_for_target(bt) == 256);
	nbits_to_target(0x17034219, bt);                           // a mainnet block, ~83T
	const uint64_t cap = datum_diff_cap_for_target(bt);
	get_target_from_diff(t, cap);
	datum_test(compare_hashes(bt, t) <= 0);                    // the cap's target takes every block
	get_target_from_diff(t, cap + 1);
	datum_test(compare_hashes(bt, t) > 0);                     // and one more would not
	datum_test(cap > 80000000000000ULL && cap < 90000000000000ULL);
	
	// What the client is told.
	datum_test(datum_stratum_client_diff(65536, 1) == 1);
	datum_test(datum_stratum_client_diff(524288, 256) == 256);
	datum_test(datum_stratum_client_diff(65536, cap) == 65536);
	datum_test(datum_stratum_client_diff(65536, 0) == 65536);  // no cap known
	datum_test(datum_stratum_client_diff(0, 1) == 1);
	
	// A share at the client's target goes to the pool only if it meets the pool difficulty.
	unsigned char h[32];
	get_target_from_diff(h, 4);                                // a hash right at difficulty 4
	datum_test(!datum_stratum_share_is_for_pool(h, 1, 8));
	datum_test(datum_stratum_share_is_for_pool(h, 1, 4));
	datum_test(datum_stratum_share_is_for_pool(h, 8, 8));      // not capped: the target checked was the pool's
	get_target_from_diff(h, 16);
	datum_test(datum_stratum_share_is_for_pool(h, 1, 8));
	printf("  the share difficulty is capped at the network's; the pool gets only shares at its own\n");
	
	// Through send_mining_notify, for a client with a d= floor of 524288.
	T_DATUM_THREAD_DATA *td = calloc(1, sizeof(*td));
	T_DATUM_STRATUM_THREADPOOL_DATA *sd = calloc(1, sizeof(*sd));
	T_DATUM_CLIENT_DATA *c = calloc(1, sizeof(*c));
	T_DATUM_MINER_DATA *m = calloc(1, sizeof(*m));
	static T_DATUM_STRATUM_JOB jmin, jmain;
	if (!datum_test(td && sd && c && m)) return;
	td->app_thread_data = sd;
	c->datum_thread = td;
	c->app_client_data = m;
	m->sdata = sd;
	m->current_diff = 524288;
	m->forced_high_min_diff = 524288;
	
	fake_job(&jmin, 7, 0x1d00ffff);
	sd->cur_stratum_job = &jmin;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	datum_test(last_set_difficulty(c) == 1);
	datum_test(m->last_sent_stratum_diff == 1 && m->last_sent_diff == 524288);
	datum_test(m->stratum_job_sdiffs[7] == 1 && m->stratum_job_diffs[7] == 524288);
	get_target_from_diff(t, 1);
	datum_test(!memcmp(m->stratum_job_targets[7], t, 32));
	datum_test(last_pot_byte(c, jmin.target_pot_index) == floorPoT(524288));   // the pool's difficulty in the coinbase
	// The empty work of a new block gets the same.
	c->out_buf = 0; memset(c->w_buffer, 0, 256);
	datum_test(send_mining_notify(c, true, false, true) == 0);
	datum_test(m->stratum_job_sdiffs[7] == 1 && last_pot_byte(c, jmin.target_pot_index) == floorPoT(524288));
	
	// The next job is at a mainnet difficulty: the client is told its own again.
	fake_job(&jmain, 8, 0x17034219);
	sd->cur_stratum_job = &jmain;
	c->out_buf = 0; memset(c->w_buffer, 0, 256);
	datum_test(send_mining_notify(c, true, false, false) == 0);
	datum_test(last_set_difficulty(c) == 524288);
	datum_test(m->stratum_job_sdiffs[8] == 524288 && m->stratum_job_diffs[8] == 524288);
	// The job before keeps the target its work was sent with.
	get_target_from_diff(t, 1);
	datum_test(!memcmp(m->stratum_job_targets[7], t, 32));
	
	// A quick difficulty change on a capped job: still capped.
	sd->cur_stratum_job = &jmin;
	m->current_diff = 1048576;
	c->out_buf = 0; memset(c->w_buffer, 0, 256);
	datum_test(send_mining_notify(c, true, true, false) == 0);
	datum_test(last_set_difficulty(c) == 1);
	datum_test(m->quickdiff_sdiff == 1 && m->quickdiff_value == 1048576);
	datum_test(!memcmp(m->quickdiff_target, t, 32));
	printf("  a client is sent difficulty 1 on a min-difficulty block and its own on the next, the PoT byte unchanged\n");
	
	free(m); free(c); free(sd); free(td);
}

// What a submitblock reply says. json_rpc_call returned NULL for a block taken
// and for every failure alike -- a timeout, an HTTP error, a JSON-RPC error,
// a reply that does not parse -- and the gateway called all of them success.
static void a_submitblock_reply_is_read_for_what_it_says(void) {
	char r[256];
	datum_test(datum_submitblock_outcome(200, "{\"result\":null,\"error\":null,\"id\":\"1\"}", r, sizeof(r)) == DATUM_SUBMITBLOCK_ACCEPTED);
	datum_test(datum_submitblock_outcome(200, "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":\"1\"}", r, sizeof(r)) == DATUM_SUBMITBLOCK_ACCEPTED);
	// Already there and valid: the submit thread often gets it in first.
	datum_test(datum_submitblock_outcome(200, "{\"result\":\"duplicate\",\"error\":null}", r, sizeof(r)) == DATUM_SUBMITBLOCK_ACCEPTED);
	datum_test(datum_submitblock_outcome(200, "{\"result\":\"bad-cb-amount\",\"error\":null}", r, sizeof(r)) == DATUM_SUBMITBLOCK_REJECTED && !strcmp(r, "bad-cb-amount"));
	datum_test(datum_submitblock_outcome(200, "{\"result\":\"inconclusive\",\"error\":null}", r, sizeof(r)) == DATUM_SUBMITBLOCK_REJECTED);
	datum_test(datum_submitblock_outcome(200, "{\"result\":\"duplicate-invalid\",\"error\":null}", r, sizeof(r)) == DATUM_SUBMITBLOCK_REJECTED);
	// None of these says anything about the block.
	datum_test(datum_submitblock_outcome(-1, NULL, r, sizeof(r)) == DATUM_SUBMITBLOCK_FAILED);                       // timeout, refused connection
	datum_test(datum_submitblock_outcome(500, "{\"result\":null,\"error\":{\"code\":-22,\"message\":\"Block decode failed\"}}", r, sizeof(r)) == DATUM_SUBMITBLOCK_FAILED);
	datum_test(strstr(r, "Block decode failed") != NULL);
	datum_test(datum_submitblock_outcome(200, "{\"result\":null,\"error\":{\"code\":-32603,\"message\":\"x\"}}", r, sizeof(r)) == DATUM_SUBMITBLOCK_FAILED);
	datum_test(datum_submitblock_outcome(401, "", r, sizeof(r)) == DATUM_SUBMITBLOCK_FAILED);
	datum_test(datum_submitblock_outcome(503, "{\"result\":null,\"error\":null}", r, sizeof(r)) == DATUM_SUBMITBLOCK_FAILED);
	datum_test(datum_submitblock_outcome(200, "<html>proxy error</html>", r, sizeof(r)) == DATUM_SUBMITBLOCK_FAILED);
	datum_test(datum_submitblock_outcome(200, "{\"error\":null}", r, sizeof(r)) == DATUM_SUBMITBLOCK_FAILED);  // no result at all
	datum_test(datum_submitblock_outcome(200, "{\"result\":true,\"error\":null}", r, sizeof(r)) == DATUM_SUBMITBLOCK_FAILED);
	datum_test(datum_submitblock_outcome(200, "[null]", r, sizeof(r)) == DATUM_SUBMITBLOCK_FAILED);
	printf("  a submitblock reply is a block taken only when the node says so\n");
}

// Which blocks a stratum thread hands to the node, with the clock given.
static void only_a_block_the_node_took_holds_back_the_next(void) {
	T_DATUM_STRATUM_THREADPOOL_DATA *sd = calloc(1, sizeof(*sd));
	static T_DATUM_STRATUM_JOB j1, j2, jo;
	if (!datum_test(sd != NULL)) return;
	memset(&j1, 0, sizeof(j1)); memset(&j2, 0, sizeof(j2)); memset(&jo, 0, sizeof(jo));
	memset(j1.prevhash_bin, 0x11, 32); j1.tsms = 1000;
	memset(j2.prevhash_bin, 0x11, 32); j2.tsms = 2000;
	memset(jo.prevhash_bin, 0x22, 32); jo.tsms = 3000;
	uint64_t now = 100000;
	
	datum_test(datum_stratum_block_is_wanted(sd, &j1, now));
	// The call failed (timeout, HTTP error, RPC error): nothing is known about
	// the block. It does not stop blocks on the previous block -- only the
	// same job waits a moment, so a dead node is not asked a thousand times a second.
	datum_stratum_note_block_tried(sd, &j1, DATUM_SUBMITBLOCK_FAILED, now);
	datum_test(!datum_stratum_block_is_wanted(sd, &j1, now + 1));
	datum_test(datum_stratum_block_is_wanted(sd, &j2, now + 1));          // another job on the same previous block
	datum_test(datum_stratum_block_is_wanted(sd, &j1, now + DATUM_BLOCK_RETRY_MIN_MS));
	// A stale job after a failed call: still wanted once the backoff is over.
	j1.is_stale_prevblock = true;
	datum_test(datum_stratum_block_is_wanted(sd, &j1, now + DATUM_BLOCK_RETRY_MIN_MS));
	j1.is_stale_prevblock = false;
	
	// Refused, again and again on one job: the wait doubles, up to its cap.
	now += 1000;
	datum_stratum_note_block_tried(sd, &j1, DATUM_SUBMITBLOCK_REJECTED, now);  // second miss on j1
	datum_test(!datum_stratum_block_is_wanted(sd, &j1, now + 2 * DATUM_BLOCK_RETRY_MIN_MS - 1));
	datum_test(datum_stratum_block_is_wanted(sd, &j1, now + 2 * DATUM_BLOCK_RETRY_MIN_MS));
	for (int k = 0; k < 10; k++) datum_stratum_note_block_tried(sd, &j1, DATUM_SUBMITBLOCK_REJECTED, now);
	datum_test(!datum_stratum_block_is_wanted(sd, &j1, now + DATUM_BLOCK_RETRY_MAX_MS - 1));
	datum_test(datum_stratum_block_is_wanted(sd, &j1, now + DATUM_BLOCK_RETRY_MAX_MS));
	datum_test(datum_stratum_block_is_wanted(sd, &j2, now));               // the other job is not held back
	// The node answered on this previous block: a stale job gets no more.
	j1.is_stale_prevblock = true;
	datum_test(!datum_stratum_block_is_wanted(sd, &j1, now + 60000));
	j1.is_stale_prevblock = false;
	
	// The node took one: no more on that previous block for a while, on any job.
	now += 60000;
	datum_stratum_note_block_tried(sd, &j2, DATUM_SUBMITBLOCK_ACCEPTED, now);
	datum_test(!datum_stratum_block_is_wanted(sd, &j1, now + 1));
	datum_test(!datum_stratum_block_is_wanted(sd, &j2, now + DATUM_BLOCK_ACCEPT_HOLD_MS - 1));
	datum_test(datum_stratum_block_is_wanted(sd, &jo, now + 1));          // another previous block
	// The tip moved (the job is stale): none on it, however long.
	j2.is_stale_prevblock = true;
	datum_test(!datum_stratum_block_is_wanted(sd, &j2, now + 600000));
	j2.is_stale_prevblock = false;
	// The tip is still on that previous block after the hold: the block did not stick. Again.
	datum_test(datum_stratum_block_is_wanted(sd, &j2, now + DATUM_BLOCK_ACCEPT_HOLD_MS));
	// ... and refused this time: the backoff, not the old accept, decides.
	datum_stratum_note_block_tried(sd, &j2, DATUM_SUBMITBLOCK_REJECTED, now + DATUM_BLOCK_ACCEPT_HOLD_MS);
	datum_test(!datum_stratum_block_is_wanted(sd, &j2, now + DATUM_BLOCK_ACCEPT_HOLD_MS + 1));
	datum_test(datum_stratum_block_is_wanted(sd, &j2, now + DATUM_BLOCK_ACCEPT_HOLD_MS + DATUM_BLOCK_RETRY_MIN_MS));
	
	// A new previous block starts afresh; a job slot reused for a new job is a new job.
	datum_stratum_note_block_tried(sd, &jo, DATUM_SUBMITBLOCK_REJECTED, now);
	datum_test(!datum_stratum_block_is_wanted(sd, &jo, now + 1));
	jo.tsms = 4000;
	datum_test(datum_stratum_block_is_wanted(sd, &jo, now + 1));
	datum_test(datum_stratum_block_is_wanted(sd, &j1, now + 1));          // only the last previous block is remembered
	free(sd);
	printf("  only a block the node took holds back the next on its previous block; refusals back off per job\n");
}

// The submit thread works on its own copy of the block: handed the stratum
// thread's buffer, it read it while the next block was written over it.
static void the_submit_thread_gets_its_own_copy(void) {
	char buf[64];
	strcpy(buf, "{\"params\":[\"block one\"]}");
	datum_submitblock_trigger(buf, "hash1");
	strcpy(buf, "{\"params\":[\"block two\"]}");
	const char *p = datum_submitblock_pending();
	datum_test(p != NULL && p != buf && !strcmp(p, "{\"params\":[\"block one\"]}"));
	datum_submitblock_trigger(buf, "hash2");
	p = datum_submitblock_pending();
	datum_test(p != NULL && p != buf && !strcmp(p, "{\"params\":[\"block two\"]}"));
	printf("  the submit thread gets its own copy of a block\n");
}

void datum_stratum_tests(void) {
	a_submitblock_reply_is_read_for_what_it_says();
	only_a_block_the_node_took_holds_back_the_next();
	the_submit_thread_gets_its_own_copy();
	the_client_difficulty_never_exceeds_the_networks();
	coinbase_types_by_name_and_rule();
	a_dropped_bmm_accept_makes_a_coinbase_unservable();
	datum_stratum_mod_username_tests();
}
