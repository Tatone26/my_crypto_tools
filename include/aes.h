#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16
#define AES_ROUNDS 10

typedef struct
{
    uint8_t round_keys[AES_KEY_SIZE * (AES_ROUNDS + 1)];
} aes128_ctx;

// Core key schedule
void aes128_init(aes128_ctx *ctx, const uint8_t key[AES_KEY_SIZE]);

// Elementary state transformations (in-place on a 4x4 matrix: uint8_t state[4][4])
void aes_sub_bytes(uint8_t state[4][4]);
void aes_inv_sub_bytes(uint8_t state[4][4]);

void aes_shift_rows(uint8_t state[4][4]);
void aes_inv_shift_rows(uint8_t state[4][4]);

void aes_mix_columns(uint8_t state[4][4]);
void aes_inv_mix_columns(uint8_t state[4][4]);

void aes_add_round_key(uint8_t state[4][4], const uint8_t round_key[AES_BLOCK_SIZE]);

// Single 16-byte block operations
void aes128_encrypt_block(const aes128_ctx *ctx, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);
void aes128_decrypt_block(const aes128_ctx *ctx, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);

#define AES_IV_SIZE AES_BLOCK_SIZE // 16 bytes

// Buffer-size calculation helper
size_t aes_cbc_padded_size(size_t in_len);

// Raw block-aligned CBC operations (no padding added or removed)
void aes128_cbc_encrypt_raw(const aes128_ctx *ctx,
                            const uint8_t iv[AES_IV_SIZE],
                            const uint8_t *in,
                            uint8_t *out,
                            size_t blocks);

void aes128_cbc_decrypt_raw(const aes128_ctx *ctx,
                            const uint8_t iv[AES_IV_SIZE],
                            const uint8_t *in,
                            uint8_t *out,
                            size_t blocks);

// End-to-end CBC with PKCS#7 padding
// Returns total ciphertext bytes written to 'out' (which is always a multiple of 16)
size_t aes128_cbc_encrypt_pkcs7(const aes128_ctx *ctx,
                                const uint8_t iv[AES_IV_SIZE],
                                const uint8_t *in,
                                size_t in_len,
                                uint8_t *out);

// Returns true on valid PKCS#7 unpadding and populates *out_len with unpadded byte count;
// returns false if padding is corrupt (tampered or wrong key/IV).
bool aes128_cbc_decrypt_pkcs7(const aes128_ctx *ctx,
                              const uint8_t iv[AES_IV_SIZE],
                              const uint8_t *in,
                              size_t in_len,
                              uint8_t *out,
                              size_t *out_len);

inline size_t aes128_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16],
                                 const uint8_t *in, size_t in_len, uint8_t *out)
{
    aes128_ctx ctx;
    aes128_init(&ctx, key);
    return aes128_cbc_encrypt_pkcs7(&ctx, iv, in, in_len, out);
}

#endif // AES_H