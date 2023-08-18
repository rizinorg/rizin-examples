// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_util.h>

#define SAMPLECRYPTO_KEY_SIZE 1

typedef struct samplecrypto_s {
	ut8 key;
} samplecrypto_t;

static bool samplecrypto_init_state(samplecrypto_t *const state, const ut8 *key, int keylen) {
	if (!state || !key || keylen != SAMPLECRYPTO_KEY_SIZE) {
		return false;
	}
	state->key = key[0];
	return true;
}

static void samplecrypto_crypt(samplecrypto_t *const state, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	for (int i = 0; i < buflen; i++) {
		outbuf[i] = inbuf[i] ^ state->key;
	}
}

static bool samplecrypto_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	rz_return_val_if_fail(cry->user, 0);
	samplecrypto_t *st = (samplecrypto_t *)cry->user;

	return samplecrypto_init_state(st, key, keylen);
}

static int samplecrypto_get_key_size(RzCrypto *cry) {
	rz_return_val_if_fail(cry->user, 0);
	return SAMPLECRYPTO_KEY_SIZE;
}

static bool samplecrypto_use(const char *algo) {
	return !strcmp(algo, "samplecrypto");
}

static bool samplecrypto_update(RzCrypto *cry, const ut8 *input, int len) {
	rz_return_val_if_fail(cry->user, false);
	samplecrypto_t *st = (samplecrypto_t *)cry->user;

	ut8 *output = malloc(len);
	if (!output) {
		return false;
	}
	samplecrypto_crypt(st, input, output, len);
	rz_crypto_append(cry, output, len);
	free(output);
	return true;
}

static bool samplecrypto_final(RzCrypto *cry, const ut8 *buf, int len) {
	return samplecrypto_update(cry, buf, len);
}

static bool samplecrypto_init(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);
	cry->user = RZ_NEW0(samplecrypto_t);
	return cry->user != NULL;
}

static bool samplecrypto_fini(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);
	RZ_FREE(cry->user);
	return true;
}

RzCryptoPlugin rz_crypto_plugin_samplecrypto = {
	.name = "samplecrypto",
	.author = "RizinOrg",
	.license = "LGPL3",
	.set_key = samplecrypto_set_key,
	.get_key_size = samplecrypto_get_key_size,
	.use = samplecrypto_use,
	.update = samplecrypto_update,
	.final = samplecrypto_final,
	.init = samplecrypto_init,
	.fini = samplecrypto_fini,
};

RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_samplecrypto,
	.version = RZ_VERSION
};
