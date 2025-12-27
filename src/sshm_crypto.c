#include "sshm_crypto.h"
#include "sshm_utils.h"
#include <sodium.h>
#include <string.h>
#include <stdatomic.h>

/* Ensure sodium initialized once */
static atomic_int _sodium_inited = 0;
static int _ensure_sodium(void) {
    if (atomic_load(&_sodium_inited)) return 0;
    if (sodium_init() < 0) {
        sshm_debug("[crypto]", "sodium_init failed");
        return -1;
    }
    atomic_store(&_sodium_inited, 1);
    return 0;
}

/* unify key length */
#ifndef SSHM_KEYBYTES
#ifdef SSHM_KEY_BYTES
#define SSHM_KEYBYTES SSHM_KEY_BYTES
#else
#define SSHM_KEYBYTES 32
#endif
#endif

int sshm_encrypt(const uint8_t *key, const void *pt, size_t pt_len, void *ct, size_t *ct_len){
    if (!key || !pt || !ct || !ct_len) return -1;
    if (_ensure_sodium() != 0) return -1;
    unsigned char *out = (unsigned char*)ct;
    unsigned long long cbytes = 0;
    /* first 24 bytes nonce */
    unsigned char *nonce = out;
    randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            out + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, &cbytes,
            (const unsigned char*)pt, (unsigned long long)pt_len,
            NULL, 0, NULL,
            nonce, key) != 0) {
        sshm_debug("[crypto]", "encrypt len=%zu result=ERR", pt_len);
        return -1;
    }
    *ct_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + (size_t)cbytes;
    sshm_debug("[crypto]", "encrypt len=%zu result=OK", pt_len);
    return 0;
}

int sshm_decrypt(const uint8_t *key, const void *ct, size_t ct_len, void *pt, size_t *pt_len){
    if (!key || !ct || !pt || !pt_len) return -1;
    if (_ensure_sodium() != 0) return -1;
    if (ct_len < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        sshm_debug("[crypto]", "decrypt len=%zu result=ERR-short", ct_len);
        return -1;
    }
    const unsigned char *in = (const unsigned char*)ct;
    const unsigned char *nonce = in;
    const unsigned char *cbuf = in + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    unsigned long long pbytes = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            (unsigned char*)pt, &pbytes, NULL,
            cbuf, (unsigned long long)(ct_len - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES),
            NULL, 0,
            nonce, key) != 0) {
        sshm_debug("[crypto]", "decrypt len=%zu result=ERR", ct_len);
        return -1;
    }
    *pt_len = (size_t)pbytes;
    sshm_debug("[crypto]", "decrypt len=%zu result=OK", ct_len);
    return 0;
}