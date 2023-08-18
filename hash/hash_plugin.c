// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_hash.h>
#include <rz_endian.h>
#include <rz_util/rz_assert.h>

#define SAMPLEHASH_START_HASH   0x3805085c0c2a533aull
#define SAMPLEHASH_CONST_HASH   0x0101010101010101ull
#define SAMPLEHASH_END_HASH     0x4f800aa42a5d017eull
#define SAMPLEHASH_DIGEST_SIZE  sizeof(ut64)
#define SAMPLEHASH_BLOCK_LENGTH sizeof(ut64)

typedef struct samplehash_s {
	ut64 hash;
} samplehash_t;

static void *plugin_samplehash_context_new() {
	return RZ_NEW0(samplehash_t);
}

static void plugin_samplehash_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_samplehash_digest_size(void *context) {
	return SAMPLEHASH_DIGEST_SIZE;
}

static RzHashSize plugin_samplehash_block_size(void *context) {
	return SAMPLEHASH_BLOCK_LENGTH;
}

static bool plugin_samplehash_init(void *user) {
	rz_return_val_if_fail(user, false);
	samplehash_t *context = (samplehash_t *)user;
	context->hash = SAMPLEHASH_START_HASH;
	return true;
}

static ut64 rotate_left(ut64 x, ut64 sh) {
	return (x << sh) | ((x >> (32 - sh)) & ~((-1 >> sh) << sh));
}

static bool plugin_samplehash_update(void *user, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(user && data, false);
	samplehash_t *context = (samplehash_t *)user;

	// very simple hash by rotating and xoring
	for (ut64 i = 0; i < size; ++i) {
		ut64 rotate = rotate_left(context->hash, 11);
		ut64 segment = SAMPLEHASH_CONST_HASH * data[i];
		context->hash = rotate ^ segment;
	}
	return true;
}

static bool plugin_samplehash_final(void *user, ut8 *digest) {
	rz_return_val_if_fail(user && digest, false);
	samplehash_t *context = (samplehash_t *)user;

	ut64 rotate = rotate_left(context->hash, 11);
	context->hash = rotate ^ SAMPLEHASH_END_HASH;
	rz_write_be64(digest, context->hash);
	return true;
}

static bool plugin_samplehash_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(SAMPLEHASH_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	samplehash_t ctx;
	plugin_samplehash_init(&ctx);
	plugin_samplehash_update(&ctx, data, size);
	plugin_samplehash_final(&ctx, dgst);

	*digest = dgst;
	if (digest_size) {
		*digest_size = SAMPLEHASH_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_samplehash = {
	.name = "samplehash",
	.license = "LGPL3",
	.author = "RizinOrg",
	.support_hmac = false,
	.context_new = plugin_samplehash_context_new,
	.context_free = plugin_samplehash_context_free,
	.digest_size = plugin_samplehash_digest_size,
	.block_size = plugin_samplehash_block_size,
	.init = plugin_samplehash_init,
	.update = plugin_samplehash_update,
	.final = plugin_samplehash_final,
	.small_block = plugin_samplehash_small_block,
};

RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_samplehash,
	.version = RZ_VERSION
};
