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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <pthread.h>
#include <jansson.h>

#include "datum_utils.h"
#include "datum_conf.h"
#include "datum_jsonrpc.h"

pthread_mutex_t submitblock_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t submitblock_cond = PTHREAD_COND_INITIALIZER;
int submit_block_triggered = 0;
char *submitblock_ptr = NULL;
char submitblock_hash[256] = { 0 };

// preciousblock tells a node to prefer our block when two race at one height.
//
// It goes wherever the block went. A BIP300 enforcer proxies submitblock to
// Bitcoin Core but implements nothing else -- preciousblock comes back "method
// not found" -- so a gateway taking templates from an enforcer silently loses
// the tiebreaker unless this follows the block to a node that has it.
void preciousblock(CURL *curl, const char *url, char *blockhash) {
	json_t *json;
	char rpc_data[384];
	
	snprintf(rpc_data, sizeof(rpc_data), "{\"jsonrpc\":\"2.0\",\"method\":\"preciousblock\",\"params\":[\"%s\"],\"id\":1}", blockhash);
	if (url) {
		json = json_rpc_call(curl, url, NULL, rpc_data);
	} else {
		json = bitcoind_json_rpc_call(curl, &datum_config, rpc_data);
	}
	if (!json) return;
	
	json_decref(json);
	return;
}

void datum_submitblock_doit(CURL *tcurl, char *url, const char *submitblock_req, const char *block_hash_hex) {
	char reason[256];
	// TODO: Move these types of things to the conf file
	const int outcome = bitcoind_submitblock(tcurl, &datum_config, url, submitblock_req, reason, sizeof(reason));
	if (outcome == DATUM_SUBMITBLOCK_ACCEPTED) {
		DLOG_INFO("Block %s submitted to upstream node successfully!%s%s", block_hash_hex, reason[0] ? " " : "", reason);
	} else if (outcome == DATUM_SUBMITBLOCK_REJECTED) {
		DLOG_WARN("Upstream node rejected our block! (%s)", reason);
	} else {
		DLOG_WARN("Could not submit our block %s: %s", block_hash_hex, reason);
	}
	
	// precious block, to the same place the block went.
	preciousblock(tcurl, url, submitblock_hash);
}

void *datum_submitblock_thread(void *ptr) {
	CURL *tcurl = NULL;
	int i;
	char *req;
	char hash[sizeof(submitblock_hash)];
	
	tcurl = curl_easy_init();
	if (!tcurl) {
		DLOG_FATAL("Could not initialize cURL for submitblock!!! This is REALLY REALLY BAD.  Like accidentally calling your wife your ex-girlfriend's name bad.");
		panic_from_thread(__LINE__);
	}
	
	DLOG_DEBUG("Submitblock thread active");
	
	while (1) {
		pthread_mutex_lock(&submitblock_mutex);
		while (!submit_block_triggered) {
			pthread_cond_wait(&submitblock_cond, &submitblock_mutex);
		}
		// Ours now: the submission is our own copy, taken under the lock and
		// worked on without it, so the next block can be queued meanwhile.
		req = submitblock_ptr;
		submitblock_ptr = NULL;
		memcpy(hash, submitblock_hash, sizeof(hash));
		submit_block_triggered = 0;
		pthread_mutex_unlock(&submitblock_mutex);
		
		if (req != NULL) {
			DLOG_DEBUG("SUBMITTING BLOCK TO OUR NODE!");
			
			datum_submitblock_doit(tcurl,NULL,req,hash);
			
			if (datum_config.extra_block_submissions_count > 0) {
				for(i=0;i<datum_config.extra_block_submissions_count;i++) {
					DLOG_DEBUG("SUBMITTING BLOCK TO EXTRA NODE %d!",i+1);
					datum_submitblock_doit(tcurl,(char *)datum_config.extra_block_submissions_urls[i],req,hash);
				}
			}
			free(req);
		}
	}
	
	return NULL;
}

void datum_submitblock_waitfree(void) {
	// The thread works on its own copy (datum_submitblock_trigger): nothing of
	// the caller's is held. Kept for callers that wait anyway.
	pthread_mutex_lock(&submitblock_mutex);
	pthread_mutex_unlock(&submitblock_mutex);
}

// The submission the thread has queued and not yet taken, or NULL. For the tests.
const char *datum_submitblock_pending(void) {
	return submitblock_ptr;
}

void datum_submitblock_trigger(const char *ptr, const char *hash) {
	// The thread gets its own copy. Handed the caller's buffer -- the stratum
	// thread's submitblock_req -- it read it while the next block found on that
	// thread was written over it, and submitted a mix of the two.
	char *copy = strdup(ptr);
	if (!copy) {
		DLOG_ERROR("Could not copy a block for the submit thread; the stratum thread still submits it.");
		return;
	}
	pthread_mutex_lock(&submitblock_mutex);
	// One not yet taken is superseded, as it always was; the stratum thread
	// submits every block itself as well.
	free(submitblock_ptr);
	submitblock_ptr = copy;
	snprintf(submitblock_hash, sizeof(submitblock_hash), "%s", hash);
	submit_block_triggered = 1;
	pthread_cond_signal(&submitblock_cond);
	pthread_mutex_unlock(&submitblock_mutex);
}

void datum_submitblock_init(void) {
	// TODO: Handle rare issues.
	pthread_t pthread_datum_submitblock_thread;
	pthread_create(&pthread_datum_submitblock_thread, NULL, datum_submitblock_thread, NULL);
	return;
}
