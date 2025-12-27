#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Encrypts plaintext into ciphertext buffer.
 * Output format: [24-byte nonce][ciphertext_with_auth_tag]
 * *ct_len is set to total bytes written.
 * Returns 0 on success, -1 on error.
 */
int sshm_encrypt(const uint8_t *key,
                 const void *pt, size_t pt_len,
                 void *ct, size_t *ct_len);

/* Decrypts buffer in format [nonce][ciphertext] into plaintext.
 * *pt_len is set to bytes written. Returns 0 on success, -1 on error.
 */
int sshm_decrypt(const uint8_t *key,
                 const void *ct, size_t ct_len,
                 void *pt, size_t *pt_len);

#ifdef __cplusplus
}
#endif
