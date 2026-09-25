/**
 * Custom implementation of AES-128 (at least, I tried)
 */

#include "aes.h"

static const uint8_t sbox[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

#define ROTL8(x) (((x) << 8) | ((x) >> 24))

static inline uint32_t sub_word32(uint32_t w)
{
    return ((uint32_t)sbox[(w >> 24) & 0xFF] << 24) |
           ((uint32_t)sbox[(w >> 16) & 0xFF] << 16) |
           ((uint32_t)sbox[(w >> 8) & 0xFF] << 8) |
           ((uint32_t)sbox[(w) & 0xFF]);
}

// Key expansion
void aes128_init(aes128_ctx *ctx, const uint8_t key_eight[AES_KEY_SIZE])
{
    static const uint32_t rci[11] = {
        0x00000000, 0x01000000, 0x02000000, 0x04000000,
        0x08000000, 0x10000000, 0x20000000, 0x40000000,
        0x80000000, 0x1B000000, 0x36000000};

    const int N = AES_KEY_SIZE / 4;
    const int R = AES_ROUNDS + 1;

    uint32_t w[44];

    // Load words in BIG-ENDIAN order: byte 0 is at bits 24..31
    for (int i = 0; i < N; i++)
    {
        w[i] = ((uint32_t)key_eight[4 * i + 0] << 24) |
               ((uint32_t)key_eight[4 * i + 1] << 16) |
               ((uint32_t)key_eight[4 * i + 2] << 8) |
               ((uint32_t)key_eight[4 * i + 3]);
    }

    // do expansion
    for (int i = N; i < 4 * R; i++)
    {
        if (i >= N && i % N == 0)
            w[i] = w[i - N] ^ sub_word32(ROTL8(w[i - 1])) ^ rci[i / N];
        else if (i >= N && N > 6 && i % N == 4)
            w[i] = w[i - N] ^ sub_word32(w[i - 1]);
        else
            w[i] = w[i - N] ^ w[i - 1];
    }

    // Store words back into ctx->round_keys in BIG-ENDIAN order
    for (int i = 0; i < 4 * R; i++)
    {
        ctx->round_keys[4 * i + 0] = (uint8_t)(w[i] >> 24);
        ctx->round_keys[4 * i + 1] = (uint8_t)(w[i] >> 16);
        ctx->round_keys[4 * i + 2] = (uint8_t)(w[i] >> 8);
        ctx->round_keys[4 * i + 3] = (uint8_t)(w[i]);
    }
}

// Elementary state transformations (in-place on a 4x4 matrix: uint8_t state[4][4])
void aes_sub_bytes(uint8_t state[4][4])
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            state[i][j] = sbox[state[i][j]];
}
void aes_inv_sub_bytes(uint8_t state[4][4])
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            state[i][j] = rsbox[state[i][j]];
}

void aes_inv_shift_rows(uint8_t state[4][4])
{
    for (int i = 1; i < 4; i++)
    {
        uint32_t temp = *(uint32_t *)(state[i]);
        uint32_t res = (temp << 8 * i) | (temp >> (4 - i) * 8);
        *(uint32_t *)(state[i]) = res;
    }
}
void aes_shift_rows(uint8_t state[4][4])
{
    for (int i = 1; i < 4; i++)
    {
        uint32_t temp = *(uint32_t *)(state[i]);
        uint32_t res = (temp >> 8 * i) | (temp << (4 - i) * 8);
        *(uint32_t *)(state[i]) = res;
    }
}

// MixColumns is a courtoisie of Gemini. I didn't have the courage to implement all of that cleanly.
static inline uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}
void aes_mix_columns(uint8_t state[4][4])
{
    for (int c = 0; c < 4; c++)
    {
        uint8_t a = state[0][c];
        uint8_t b = state[1][c];
        uint8_t d = state[2][c];
        uint8_t e = state[3][c];

        uint8_t t = a ^ b ^ d ^ e;

        state[0][c] ^= t ^ xtime(a ^ b);
        state[1][c] ^= t ^ xtime(b ^ d);
        state[2][c] ^= t ^ xtime(d ^ e);
        state[3][c] ^= t ^ xtime(e ^ a);
    }
}
static inline uint8_t mul_gf(uint8_t a, uint8_t b)
{
    uint8_t res = 0;
    while (b)
    {
        if (b & 1)
            res ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return res;
}

void aes_inv_mix_columns(uint8_t state[4][4])
{
    for (int c = 0; c < 4; c++)
    {
        uint8_t a = state[0][c];
        uint8_t b = state[1][c];
        uint8_t d = state[2][c];
        uint8_t e = state[3][c];

        state[0][c] = mul_gf(a, 0x0E) ^ mul_gf(b, 0x0B) ^ mul_gf(d, 0x0D) ^ mul_gf(e, 0x09);
        state[1][c] = mul_gf(a, 0x09) ^ mul_gf(b, 0x0E) ^ mul_gf(d, 0x0B) ^ mul_gf(e, 0x0D);
        state[2][c] = mul_gf(a, 0x0D) ^ mul_gf(b, 0x09) ^ mul_gf(d, 0x0E) ^ mul_gf(e, 0x0B);
        state[3][c] = mul_gf(a, 0x0B) ^ mul_gf(b, 0x0D) ^ mul_gf(d, 0x09) ^ mul_gf(e, 0x0E);
    }
}

void aes_add_round_key(uint8_t state[4][4], const uint8_t round_key[AES_BLOCK_SIZE])
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            state[i][j] = state[i][j] ^ round_key[j * 4 + i];
}

// Single 16-byte block operations
void aes128_encrypt_block(const aes128_ctx *ctx, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE])
{
    uint8_t state[4][4];

    // 1. Load input block into 4x4 state (column-major order)
    for (int c = 0; c < 4; c++)
    {
        for (int r = 0; r < 4; r++)
        {
            state[r][c] = in[c * 4 + r];
        }
    }

    aes_add_round_key(state, &ctx->round_keys[0]);

    for (int round = 1; round < AES_ROUNDS; round++)
    {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, &ctx->round_keys[round * AES_BLOCK_SIZE]);
    }

    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, &ctx->round_keys[AES_ROUNDS * AES_BLOCK_SIZE]);

    // Unload state into output block (column-major order)
    for (int c = 0; c < 4; c++)
    {
        for (int r = 0; r < 4; r++)
        {
            out[c * 4 + r] = state[r][c];
        }
    }
}

void aes128_decrypt_block(const aes128_ctx *ctx, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE])
{
    uint8_t state[4][4];

    // 1. Load ciphertext block into 4x4 state (column-major order)
    for (int c = 0; c < 4; c++)
    {
        for (int r = 0; r < 4; r++)
        {
            state[r][c] = in[c * 4 + r];
        }
    }

    aes_add_round_key(state, &ctx->round_keys[AES_ROUNDS * AES_BLOCK_SIZE]);

    for (int round = AES_ROUNDS - 1; round >= 1; round--)
    {
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state);
        aes_add_round_key(state, &ctx->round_keys[round * AES_BLOCK_SIZE]);
        aes_inv_mix_columns(state);
    }

    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    aes_add_round_key(state, &ctx->round_keys[0]);

    // Unload state into plaintext output block (column-major order)
    for (int c = 0; c < 4; c++)
    {
        for (int r = 0; r < 4; r++)
        {
            out[c * 4 + r] = state[r][c];
        }
    }
}

#define AES_IV_SIZE AES_BLOCK_SIZE // 16 bytes

// Buffer-size calculation helper
// return in_len + 16 if in_len is a multiple of 16
size_t aes_cbc_padded_size(size_t in_len)
{
    return in_len + (16 - in_len % 16);
}

// Raw block-aligned CBC operations (no padding added or removed)
void aes128_cbc_encrypt_raw(const aes128_ctx *ctx,
                            const uint8_t iv[AES_IV_SIZE],
                            const uint8_t *in,
                            uint8_t *out,
                            size_t blocks)
{
    uint8_t feedback[AES_IV_SIZE];
    for (int i = 0; i < AES_IV_SIZE; i++)
        feedback[i] = iv[i];

    uint8_t temp2[AES_BLOCK_SIZE];

    for (int b = 0; b < (int)blocks; b++)
    {
        for (int i = 0; i < AES_IV_SIZE; i++)
            temp2[i] = feedback[i] ^ in[b * AES_BLOCK_SIZE + i];
        aes128_encrypt_block(ctx, temp2, feedback);

        for (int i = 0; i < AES_BLOCK_SIZE; i++)
            out[b * AES_BLOCK_SIZE + i] = feedback[i];
    }
}

void aes128_cbc_decrypt_raw(const aes128_ctx *ctx,
                            const uint8_t iv[AES_IV_SIZE],
                            const uint8_t *in,
                            uint8_t *out,
                            size_t blocks)
{
    for (size_t b = 0; b < blocks; b++) // easy loop to parallelize
    {
        uint8_t temp2[AES_IV_SIZE];
        aes128_decrypt_block(ctx, in + (b * AES_BLOCK_SIZE), temp2);

        for (size_t i = 0; i < AES_BLOCK_SIZE; i++)
            out[b * AES_BLOCK_SIZE + i] = temp2[i] ^ (b > 0 ? in[(b - 1) * AES_BLOCK_SIZE + i] : iv[i]);
    }
}

// End-to-end CBC with PKCS#7 padding
// Returns total ciphertext bytes written to 'out' (which is always a multiple of 16)
size_t aes128_cbc_encrypt_pkcs7(const aes128_ctx *ctx,
                                const uint8_t iv[AES_IV_SIZE],
                                const uint8_t *in,
                                size_t in_len,
                                uint8_t *out)
{
    size_t total_bytes = aes_cbc_padded_size(in_len);
    uint8_t padding = (uint8_t)(total_bytes - in_len);
    int full_blocks = in_len / AES_BLOCK_SIZE;

    if (full_blocks > 0)
        aes128_cbc_encrypt_raw(ctx, iv, in, out, full_blocks);

    uint8_t last_block[AES_BLOCK_SIZE];
    for (int i = 0; i < AES_BLOCK_SIZE - padding; i++)
        last_block[i] = in[AES_BLOCK_SIZE * full_blocks + i];
    for (int i = AES_BLOCK_SIZE - padding; i < AES_BLOCK_SIZE; i++)
        last_block[i] = padding;

    const uint8_t *last_iv = (full_blocks == 0) ? iv : (out + (full_blocks - 1) * AES_BLOCK_SIZE);

    aes128_cbc_encrypt_raw(ctx, last_iv, last_block, out + full_blocks * AES_BLOCK_SIZE, 1);

    return total_bytes;
}

// Returns true on valid PKCS#7 unpadding and populates *out_len with unpadded byte count;
// returns false if padding is corrupt (tampered or wrong key/IV).
bool aes128_cbc_decrypt_pkcs7(const aes128_ctx *ctx,
                              const uint8_t iv[AES_IV_SIZE],
                              const uint8_t *in,
                              size_t in_len,
                              uint8_t *out,
                              size_t *out_len)
{
    if (!in || in_len == 0 || in_len % AES_BLOCK_SIZE != 0 || !out || !out_len || !ctx)
        return false;

    aes128_cbc_decrypt_raw(ctx, iv, in, out, in_len / AES_BLOCK_SIZE);
    uint8_t last_byte = out[in_len - 1];
    if (last_byte < 1 || last_byte > 16) // incorrect padding
        return false;

    for (size_t i = in_len - 1; i > in_len - 1 - last_byte; i--)
        if (out[i] != last_byte)
            return false;

    *out_len = in_len - last_byte;
    return true;
}