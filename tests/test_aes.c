#include "tests.h"
#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/evp.h>

// Forward declarations of AES & CBC functions
void aes128_init(aes128_ctx *ctx, const uint8_t key[AES_KEY_SIZE]);
void aes_sub_bytes(uint8_t state[4][4]);
void aes_inv_sub_bytes(uint8_t state[4][4]);
void aes_shift_rows(uint8_t state[4][4]);
void aes_inv_shift_rows(uint8_t state[4][4]);
void aes_mix_columns(uint8_t state[4][4]);
void aes_inv_mix_columns(uint8_t state[4][4]);
void aes_add_round_key(uint8_t state[4][4], const uint8_t round_key[AES_BLOCK_SIZE]);

void aes128_encrypt_block(const aes128_ctx *ctx, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);
void aes128_decrypt_block(const aes128_ctx *ctx, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);

size_t aes_cbc_padded_size(size_t in_len);
void aes128_cbc_encrypt_raw(const aes128_ctx *ctx, const uint8_t iv[AES_IV_SIZE], const uint8_t *in, uint8_t *out, size_t blocks);
void aes128_cbc_decrypt_raw(const aes128_ctx *ctx, const uint8_t iv[AES_IV_SIZE], const uint8_t *in, uint8_t *out, size_t blocks);
size_t aes128_cbc_encrypt_pkcs7(const aes128_ctx *ctx, const uint8_t iv[AES_IV_SIZE], const uint8_t *in, size_t in_len, uint8_t *out);
bool aes128_cbc_decrypt_pkcs7(const aes128_ctx *ctx, const uint8_t iv[AES_IV_SIZE], const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);

// ============================================================================
// NIST FIPS 197 OFFICIAL SPECIFICATION VECTORS
// ============================================================================

static const uint8_t NIST_KEY[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

static const uint8_t NIST_EXPANDED_KEYS[176] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05,
    0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f,
    0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e, 0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b,
    0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f, 0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00,
    0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc,
    0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00, 0x93, 0xfd,
    0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6, 0xdc, 0x4f,
    0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b, 0xf5, 0x60, 0x7f, 0x8d, 0x29, 0x2f,
    0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e,
    0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6};

static const uint8_t NIST_PT[16] = {
    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

static const uint8_t NIST_R1_START[4][4] = {
    {0x19, 0xa0, 0x9a, 0xe9},
    {0x3d, 0xf4, 0xc6, 0xf8},
    {0xe3, 0xe2, 0x8d, 0x48},
    {0xbe, 0x2b, 0x2a, 0x08}};

static const uint8_t NIST_R1_SUB_BYTES[4][4] = {
    {0xd4, 0xe0, 0xb8, 0x1e},
    {0x27, 0xbf, 0xb4, 0x41},
    {0x11, 0x98, 0x5d, 0x52},
    {0xae, 0xf1, 0xe5, 0x30}};

static const uint8_t NIST_R1_SHIFT_ROWS[4][4] = {
    {0xd4, 0xe0, 0xb8, 0x1e},
    {0xbf, 0xb4, 0x41, 0x27},
    {0x5d, 0x52, 0x11, 0x98},
    {0x30, 0xae, 0xf1, 0xe5}};

static const uint8_t NIST_R1_MIX_COLUMNS[4][4] = {
    {0x04, 0xe0, 0x48, 0x28},
    {0x66, 0xcb, 0xf8, 0x06},
    {0x81, 0x19, 0xd3, 0x26},
    {0xe5, 0x9a, 0x7a, 0x4c}};

// ============================================================================
// DIAGNOSTIC PRINTERS
// ============================================================================

static void print_matrix_diff(const char *title, const uint8_t exp[4][4], const uint8_t got[4][4])
{
    printf("\n" BOLD RED "  [FAILURE] %s\n" RESET, title);
    printf("         Expected Matrix (FIPS 197)              Your Implementation\n");
    printf("    Col:   0    1    2    3                 Col:   0    1    2    3\n");
    for (int r = 0; r < 4; r++)
    {
        printf("    R%d: [ ", r);
        for (int c = 0; c < 4; c++)
            printf("%02x   ", exp[r][c]);
        printf("]          R%d: [ ", r);
        for (int c = 0; c < 4; c++)
        {
            if (got[r][c] != exp[r][c])
                printf(BOLD RED "%02x " RESET "  ", got[r][c]);
            else
                printf(GREEN "%02x " RESET "  ", got[r][c]);
        }
        printf("]\n");
    }
    printf("\n");
}

static void print_stream_diff(const char *label, const uint8_t *exp, const uint8_t *got, size_t len)
{
    printf("  %-18s = ", label);
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", exp[i]);
        if ((i + 1) % 16 == 0 && (i + 1) < len)
            printf("\n                       ");
        else if ((i + 1) % 4 == 0 && (i + 1) < len)
            printf(" ");
    }
    printf("\n  %-18s = ", "Your result");
    for (size_t i = 0; i < len; i++)
    {
        if (exp[i] != got[i])
            printf(BOLD RED "%02x" RESET, got[i]);
        else
            printf("%02x", got[i]);
        if ((i + 1) % 16 == 0 && (i + 1) < len)
            printf("\n                       ");
        else if ((i + 1) % 4 == 0 && (i + 1) < len)
            printf(" ");
    }
    printf("\n");
}

// ============================================================================
// 1. ISOLATED ELEMENTARY PRIMITIVES
// ============================================================================

static int test_primitives_nist_fips197(void)
{
    int fails = 0;
    uint8_t state[4][4];

    // A. AddRoundKey
    printf(BADGE_RUN CYAN "%-22s vs NIST FIPS 197... " RESET, "AddRoundKey (Fwd/Inv)");
    fflush(stdout);
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            state[r][c] = NIST_PT[c * 4 + r];

    aes_add_round_key(state, NIST_KEY);
    if (memcmp(state, NIST_R1_START, 16) != 0)
    {
        printf(BADGE_FAIL "\n");
        print_matrix_diff("aes_add_round_key", NIST_R1_START, state);
        return ++fails;
    }
    aes_add_round_key(state, NIST_KEY);
    for (int c = 0; c < 4; c++)
    {
        for (int r = 0; r < 4; r++)
        {
            if (state[r][c] != NIST_PT[c * 4 + r])
            {
                printf(BADGE_FAIL "\n" BOLD RED "  aes_add_round_key involution failed!\n" RESET);
                return ++fails;
            }
        }
    }
    printf(BADGE_PASS "\n");

    // B. SubBytes & InvSubBytes
    printf(BADGE_RUN CYAN "%-22s vs NIST FIPS 197... " RESET, "SubBytes & InvSubBytes");
    fflush(stdout);
    memcpy(state, NIST_R1_START, 16);
    aes_sub_bytes(state);
    if (memcmp(state, NIST_R1_SUB_BYTES, 16) != 0)
    {
        printf(BADGE_FAIL "\n");
        print_matrix_diff("aes_sub_bytes", NIST_R1_SUB_BYTES, state);
        return ++fails;
    }
    aes_inv_sub_bytes(state);
    if (memcmp(state, NIST_R1_START, 16) != 0)
    {
        printf(BADGE_FAIL "\n");
        print_matrix_diff("aes_inv_sub_bytes", NIST_R1_START, state);
        return ++fails;
    }
    printf(BADGE_PASS "\n");

    // C. ShiftRows & InvShiftRows
    printf(BADGE_RUN CYAN "%-22s vs NIST FIPS 197... " RESET, "ShiftRows & InvShift");
    fflush(stdout);
    memcpy(state, NIST_R1_SUB_BYTES, 16);
    aes_shift_rows(state);
    if (memcmp(state, NIST_R1_SHIFT_ROWS, 16) != 0)
    {
        printf(BADGE_FAIL "\n");
        print_matrix_diff("aes_shift_rows", NIST_R1_SHIFT_ROWS, state);
        return ++fails;
    }
    aes_inv_shift_rows(state);
    if (memcmp(state, NIST_R1_SUB_BYTES, 16) != 0)
    {
        printf(BADGE_FAIL "\n");
        print_matrix_diff("aes_inv_shift_rows", NIST_R1_SUB_BYTES, state);
        return ++fails;
    }
    printf(BADGE_PASS "\n");

    // D. MixColumns & InvMixColumns
    printf(BADGE_RUN CYAN "%-22s vs NIST FIPS 197... " RESET, "MixColumns & InvMix");
    fflush(stdout);
    memcpy(state, NIST_R1_SHIFT_ROWS, 16);
    aes_mix_columns(state);
    if (memcmp(state, NIST_R1_MIX_COLUMNS, 16) != 0)
    {
        printf(BADGE_FAIL "\n");
        print_matrix_diff("aes_mix_columns", NIST_R1_MIX_COLUMNS, state);
        return ++fails;
    }
    aes_inv_mix_columns(state);
    if (memcmp(state, NIST_R1_SHIFT_ROWS, 16) != 0)
    {
        printf(BADGE_FAIL "\n");
        print_matrix_diff("aes_inv_mix_columns", NIST_R1_SHIFT_ROWS, state);
        return ++fails;
    }
    printf(BADGE_PASS "\n");

    return 0;
}

static int test_primitives_random_inversion(int trials)
{
    printf(BADGE_RUN CYAN "%-22s (%d random states)... " RESET, "Primitives Round-Trip", trials);
    fflush(stdout);

    uint8_t orig[4][4], s[4][4];
    for (int t = 0; t < trials; t++)
    {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                orig[r][c] = (uint8_t)(rand() & 0xFF);

        memcpy(s, orig, 16);
        aes_sub_bytes(s);
        aes_inv_sub_bytes(s);
        if (memcmp(s, orig, 16) != 0)
        {
            printf(BADGE_FAIL "\n");
            print_matrix_diff("InvSubBytes(SubBytes(state)) != state", orig, s);
            return 1;
        }

        memcpy(s, orig, 16);
        aes_shift_rows(s);
        aes_inv_shift_rows(s);
        if (memcmp(s, orig, 16) != 0)
        {
            printf(BADGE_FAIL "\n");
            print_matrix_diff("InvShiftRows(ShiftRows(state)) != state", orig, s);
            return 1;
        }

        memcpy(s, orig, 16);
        aes_mix_columns(s);
        aes_inv_mix_columns(s);
        if (memcmp(s, orig, 16) != 0)
        {
            printf(BADGE_FAIL "\n");
            print_matrix_diff("InvMixColumns(MixColumns(state)) != state", orig, s);
            return 1;
        }
    }

    printf(BADGE_PASS "\n");
    return 0;
}

static int test_key_expansion_nist(void)
{
    printf(BADGE_RUN CYAN "%-22s vs NIST FIPS 197... " RESET, "Key Expansion");
    fflush(stdout);

    aes128_ctx ctx;
    aes128_init(&ctx, NIST_KEY);

    for (int r = 0; r < 11; r++)
    {
        if (memcmp(&ctx.round_keys[r * 16], &NIST_EXPANDED_KEYS[r * 16], 16) != 0)
        {
            printf(BADGE_FAIL "\n" BOLD RED "  Mismatch at Round %d key!\n" RESET, r);
            print_stream_diff("Expected Round Key", &NIST_EXPANDED_KEYS[r * 16], &ctx.round_keys[r * 16], 16);
            return 1;
        }
    }

    printf(BADGE_PASS "\n");
    return 0;
}

// ============================================================================
// 2. OPENSSL BACKEND HELPERS
// ============================================================================

static void ossl_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, out, &len, in, 16);
    EVP_CIPHER_CTX_free(ctx);
}

static void ossl_cbc_raw_encrypt(const uint8_t key[16], const uint8_t iv[16],
                                 const uint8_t *in, uint8_t *out, size_t blocks)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, out, &len, in, (int)(blocks * 16));
    EVP_CIPHER_CTX_free(ctx);
}

static void ossl_cbc_raw_decrypt(const uint8_t key[16], const uint8_t iv[16],
                                 const uint8_t *in, uint8_t *out, size_t blocks)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_DecryptUpdate(ctx, out, &len, in, (int)(blocks * 16));
    EVP_CIPHER_CTX_free(ctx);
}

static void ossl_cbc_pkcs7_encrypt(const uint8_t key[16], const uint8_t iv[16],
                                   const uint8_t *in, int in_len,
                                   uint8_t *out, int *out_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    *out_len = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    EVP_EncryptUpdate(ctx, out, &len, in, in_len);
    *out_len = len;
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    *out_len += len;
    EVP_CIPHER_CTX_free(ctx);
}

// ============================================================================
// 3. BLOCK CIPHER VALIDATION
// ============================================================================

static int test_block_vs_openssl(int trials)
{
    printf(BADGE_RUN CYAN "%-22s vs OpenSSL (%d random trials)... " RESET, "Block Enc/Dec", trials);
    fflush(stdout);

    uint8_t key[16], pt[16], my_ct[16], ossl_ct[16], dec[16];
    aes128_ctx ctx;

    for (int t = 0; t < trials; t++)
    {
        for (int i = 0; i < 16; i++)
        {
            key[i] = (uint8_t)(rand() & 0xFF);
            pt[i] = (uint8_t)(rand() & 0xFF);
        }

        aes128_init(&ctx, key);
        aes128_encrypt_block(&ctx, pt, my_ct);
        aes128_decrypt_block(&ctx, my_ct, dec);

        ossl_ecb_encrypt(key, pt, ossl_ct);

        if (memcmp(my_ct, ossl_ct, 16) != 0)
        {
            printf(BADGE_FAIL "\n" BOLD RED "  Block Encrypt mismatch on trial %d!\n" RESET, t);
            print_stream_diff("OpenSSL Expected", ossl_ct, my_ct, 16);
            return 1;
        }

        if (memcmp(dec, pt, 16) != 0)
        {
            printf(BADGE_FAIL "\n" BOLD RED "  Block Decrypt did not restore plaintext on trial %d!\n" RESET, t);
            print_stream_diff("Expected Plaintext", pt, dec, 16);
            return 1;
        }
    }

    printf(BADGE_PASS "\n");
    return 0;
}

// ============================================================================
// 4. CBC ENCRYPTION TESTS (RAW & PKCS#7)
// ============================================================================

static int test_cbc_raw_encrypt_vs_openssl(int trials)
{
    printf(BADGE_RUN CYAN "%-22s vs OpenSSL (%d streams)... " RESET, "CBC Raw Encrypt", trials);
    fflush(stdout);

    uint8_t key[16], iv[16];
    uint8_t pt[256], my_ct[256], ossl_ct[256];
    aes128_ctx ctx;

    for (int t = 0; t < trials; t++)
    {
        for (int i = 0; i < 16; i++)
        {
            key[i] = (uint8_t)(rand() & 0xFF);
            iv[i] = (uint8_t)(rand() & 0xFF);
        }

        size_t blocks = (size_t)(1 + (rand() % 16));
        for (size_t i = 0; i < blocks * 16; i++)
            pt[i] = (uint8_t)(rand() & 0xFF);

        aes128_init(&ctx, key);
        aes128_cbc_encrypt_raw(&ctx, iv, pt, my_ct, blocks);
        ossl_cbc_raw_encrypt(key, iv, pt, ossl_ct, blocks);

        if (memcmp(my_ct, ossl_ct, blocks * 16) != 0)
        {
            printf(BADGE_FAIL "\n" BOLD RED "  CBC Raw Encrypt failure on trial %d (%zu blocks)!\n" RESET, t, blocks);
            print_stream_diff("OpenSSL CT", ossl_ct, my_ct, blocks * 16);
            return 1;
        }
    }

    printf(BADGE_PASS "\n");
    return 0;
}

static int test_cbc_pkcs7_encrypt_vs_openssl(int trials)
{
    printf(BADGE_RUN CYAN "%-22s vs OpenSSL (%d random lengths)... " RESET, "CBC PKCS#7 Encrypt", trials);
    fflush(stdout);

    uint8_t key[16], iv[16];
    uint8_t pt[512], my_ct[528], ossl_ct[528];
    aes128_ctx ctx;

    for (int t = 0; t < trials; t++)
    {
        for (int i = 0; i < 16; i++)
        {
            key[i] = (uint8_t)(rand() & 0xFF);
            iv[i] = (uint8_t)(rand() & 0xFF);
        }

        int len = (t < 8) ? (t == 0 ? 0 : (t == 1 ? 1 : (t == 2 ? 15 : (t == 3 ? 16 : (t == 4 ? 17 : (t == 5 ? 31 : (t == 6 ? 32 : 33)))))))
                          : (rand() % 400);

        for (int i = 0; i < len; i++)
            pt[i] = (uint8_t)(rand() & 0xFF);

        aes128_init(&ctx, key);
        size_t my_ct_len = aes128_cbc_encrypt_pkcs7(&ctx, iv, pt, (size_t)len, my_ct);

        int ossl_len = 0;
        ossl_cbc_pkcs7_encrypt(key, iv, pt, len, ossl_ct, &ossl_len);

        if (my_ct_len != (size_t)ossl_len || memcmp(my_ct, ossl_ct, my_ct_len) != 0)
        {
            printf(BADGE_FAIL "\n" BOLD RED "  CBC PKCS#7 Encrypt failure at plaintext length = %d bytes!\n" RESET, len);
            print_stream_diff("OpenSSL CT", ossl_ct, my_ct, (size_t)ossl_len);
            return 1;
        }
    }

    printf(BADGE_PASS "\n");
    return 0;
}

// ============================================================================
// 5. CBC DECRYPTION TESTS (RAW & VALID PKCS#7)
// ============================================================================

static int test_cbc_raw_decrypt_vs_openssl(int trials)
{
    printf(BADGE_RUN CYAN "%-22s vs OpenSSL (%d streams)... " RESET, "CBC Raw Decrypt", trials);
    fflush(stdout);

    uint8_t key[16], iv[16];
    uint8_t ct[256], my_pt[256], ossl_pt[256];
    aes128_ctx ctx;

    for (int t = 0; t < trials; t++)
    {
        for (int i = 0; i < 16; i++)
        {
            key[i] = (uint8_t)(rand() & 0xFF);
            iv[i] = (uint8_t)(rand() & 0xFF);
        }

        size_t blocks = (size_t)(1 + (rand() % 16));
        for (size_t i = 0; i < blocks * 16; i++)
            ct[i] = (uint8_t)(rand() & 0xFF);

        aes128_init(&ctx, key);
        aes128_cbc_decrypt_raw(&ctx, iv, ct, my_pt, blocks);
        ossl_cbc_raw_decrypt(key, iv, ct, ossl_pt, blocks);

        if (memcmp(my_pt, ossl_pt, blocks * 16) != 0)
        {
            printf(BADGE_FAIL "\n" BOLD RED "  CBC Raw Decrypt failure on trial %d (%zu blocks)!\n" RESET, t, blocks);
            print_stream_diff("OpenSSL PT", ossl_pt, my_pt, blocks * 16);
            return 1;
        }
    }

    printf(BADGE_PASS "\n");
    return 0;
}

static int test_cbc_pkcs7_decrypt_vs_openssl(int trials)
{
    printf(BADGE_RUN CYAN "%-22s vs OpenSSL (%d valid lengths)... " RESET, "CBC PKCS#7 Decrypt", trials);
    fflush(stdout);

    uint8_t key[16], iv[16];
    uint8_t pt[512], ossl_ct[528], my_pt[528];
    aes128_ctx ctx;

    for (int t = 0; t < trials; t++)
    {
        for (int i = 0; i < 16; i++)
        {
            key[i] = (uint8_t)(rand() & 0xFF);
            iv[i] = (uint8_t)(rand() & 0xFF);
        }

        int len = (t < 8) ? (t == 0 ? 0 : (t == 1 ? 1 : (t == 2 ? 15 : (t == 3 ? 16 : (t == 4 ? 17 : (t == 5 ? 31 : (t == 6 ? 32 : 33)))))))
                          : (rand() % 400);

        for (int i = 0; i < len; i++)
            pt[i] = (uint8_t)(rand() & 0xFF);

        int ct_len = 0;
        ossl_cbc_pkcs7_encrypt(key, iv, pt, len, ossl_ct, &ct_len);

        aes128_init(&ctx, key);
        size_t my_pt_len = 0;
        bool ok = aes128_cbc_decrypt_pkcs7(&ctx, iv, ossl_ct, (size_t)ct_len, my_pt, &my_pt_len);

        if (!ok)
        {
            printf(BADGE_FAIL "\n" BOLD RED "  CBC PKCS#7 Decrypt rejected valid OpenSSL ciphertext at len = %d!\n" RESET, len);
            return 1;
        }

        if (my_pt_len != (size_t)len || memcmp(my_pt, pt, (size_t)len) != 0)
        {
            printf(BADGE_FAIL "\n" BOLD RED "  CBC PKCS#7 Decrypt content/length mismatch at len = %d (got %zu)!\n" RESET, len, my_pt_len);
            print_stream_diff("Expected Plaintext", pt, my_pt, (size_t)len);
            return 1;
        }
    }

    printf(BADGE_PASS "\n");
    return 0;
}

// ============================================================================
// 6. NEGATIVE & MALICIOUS PKCS#7 PADDING ORACLE TESTS
// ============================================================================

static int test_cbc_pkcs7_invalid_padding_oracle(int trials)
{
    printf(BADGE_RUN CYAN "%-22s (Edge cases, corruptions & oracles)... " RESET, "CBC PKCS#7 Oracle Neg");
    fflush(stdout);

    uint8_t key[16], iv[16];
    for (int i = 0; i < 16; i++)
    {
        key[i] = (uint8_t)(rand() & 0xFF);
        iv[i] = (uint8_t)(rand() & 0xFF);
    }

    aes128_ctx ctx;
    aes128_init(&ctx, key);

    uint8_t dummy_out[256];
    size_t out_len = 0xDEADBEEF;

    // 1. Length zero check
    if (aes128_cbc_decrypt_pkcs7(&ctx, iv, dummy_out, 0, dummy_out, &out_len))
    {
        printf(BADGE_FAIL "\n" BOLD RED "  Failed: in_len = 0 was accepted as valid ciphertext!\n" RESET);
        return 1;
    }
    if (out_len != 0xDEADBEEF)
    {
        printf(BADGE_FAIL "\n" BOLD RED "  Failed: out_len was modified on rejected in_len = 0!\n" RESET);
        return 1;
    }

    // 2. Non-block-aligned length checks (1..15, 17..31)
    const size_t bad_sizes[] = {1, 7, 15, 17, 23, 31, 33};
    for (size_t i = 0; i < sizeof(bad_sizes) / sizeof(bad_sizes[0]); i++)
    {
        out_len = 0xCAFEBABE;
        if (aes128_cbc_decrypt_pkcs7(&ctx, iv, dummy_out, bad_sizes[i], dummy_out, &out_len))
        {
            printf(BADGE_FAIL "\n" BOLD RED "  Failed: Non-multiple of 16 length (%zu) was accepted!\n" RESET, bad_sizes[i]);
            return 1;
        }
        if (out_len != 0xCAFEBABE)
        {
            printf(BADGE_FAIL "\n" BOLD RED "  Failed: out_len modified on unaligned length (%zu)!\n" RESET, bad_sizes[i]);
            return 1;
        }
    }

    // 3. Craft intentionally corrupted PKCS#7 pad patterns
    uint8_t pt_crafted[32];
    uint8_t ct_crafted[32];

    for (int t = 0; t < trials; t++)
    {
        for (int i = 0; i < 32; i++)
            pt_crafted[i] = (uint8_t)(rand() & 0xFF);

        int corrupt_mode = t % 5;
        switch (corrupt_mode)
        {
        case 0:
            pt_crafted[31] = 0x00; // 0x00 is strictly illegal
            break;
        case 1:
            pt_crafted[31] = (uint8_t)(17 + (rand() % 230)); // > 16 is illegal
            break;
        case 2:
            pt_crafted[31] = 0x04;
            pt_crafted[30] = 0x04;
            pt_crafted[29] = 0x04;
            pt_crafted[28] = 0x03; // Inconsistent multi-byte pad sequence
            break;
        case 3:
            for (int i = 16; i < 32; i++)
                pt_crafted[i] = 0x10;
            pt_crafted[16] = 0x0F; // Corrupt first byte of full 16-byte block
            break;
        case 4:
            pt_crafted[31] = 0x02;
            pt_crafted[30] = (uint8_t)(pt_crafted[31] ^ 0x01);
            break;
        }

        aes128_cbc_encrypt_raw(&ctx, iv, pt_crafted, ct_crafted, 2);

        out_len = 0xBADC0DE;
        bool accepted = aes128_cbc_decrypt_pkcs7(&ctx, iv, ct_crafted, 32, dummy_out, &out_len);
        if (accepted)
        {
            printf(BADGE_FAIL "\n" BOLD RED "  Failed: Oracle accepted invalid padding (mode %d, pad_byte=0x%02x)!\n" RESET,
                   corrupt_mode, pt_crafted[31]);
            return 1;
        }
        if (out_len != 0xBADC0DE)
        {
            printf(BADGE_FAIL "\n" BOLD RED "  Failed: out_len modified when padding verification failed!\n" RESET);
            return 1;
        }
    }

    printf(BADGE_PASS "\n");
    return 0;
}

// ============================================================================
// 7. COMPREHENSIVE MULTI-SCALE PERFORMANCE BENCHMARKS
// ============================================================================

static void bench_aes(void)
{
    print_bench_header(128, "OSSL");

    uint8_t key[16], iv[16], in[16], out[16];
    uint8_t state[4][4];
    for (int i = 0; i < 16; i++)
    {
        key[i] = (uint8_t)(rand() & 0xFF);
        iv[i] = (uint8_t)(rand() & 0xFF);
        in[i] = (uint8_t)(rand() & 0xFF);
    }
    memcpy(state, in, 16);

    aes128_ctx ctx;
    aes128_init(&ctx, key);

    const int micro_iters = 50000;
    double m_samples[7], g_samples[7];
    BenchStats st_m = {0}, st_g = {0};

    // ------------------------------------------------------------------------
    // 1. Primitives Micro-benchmarks
    // ------------------------------------------------------------------------
    for (int s = 0; s < 7; s++)
    {
        double t0 = get_ns();
        for (int i = 0; i < micro_iters; i++)
            aes_sub_bytes(state);
        m_samples[s] = (get_ns() - t0) / (double)micro_iters;
        g_samples[s] = 0.0;
    }
    compute_stats(m_samples, 7, &st_m);
    compute_stats(g_samples, 7, &st_g);
    print_bench_row("aes_sub_bytes", &st_m, &st_g);

    for (int s = 0; s < 7; s++)
    {
        double t0 = get_ns();
        for (int i = 0; i < micro_iters; i++)
            aes_shift_rows(state);
        m_samples[s] = (get_ns() - t0) / (double)micro_iters;
        g_samples[s] = 0.0;
    }
    compute_stats(m_samples, 7, &st_m);
    compute_stats(g_samples, 7, &st_g);
    print_bench_row("aes_shift_rows", &st_m, &st_g);

    for (int s = 0; s < 7; s++)
    {
        double t0 = get_ns();
        for (int i = 0; i < micro_iters; i++)
            aes_mix_columns(state);
        m_samples[s] = (get_ns() - t0) / (double)micro_iters;
        g_samples[s] = 0.0;
    }
    compute_stats(m_samples, 7, &st_m);
    compute_stats(g_samples, 7, &st_g);
    print_bench_row("aes_mix_columns", &st_m, &st_g);

    // ------------------------------------------------------------------------
    // 2. Single Block ECB (16 Bytes)
    // ------------------------------------------------------------------------
    EVP_CIPHER_CTX *ecb_enc_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ecb_enc_ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ecb_enc_ctx, 0);

    for (int s = 0; s < 7; s++)
    {
        double t0 = get_ns();
        for (int i = 0; i < micro_iters; i++)
            aes128_encrypt_block(&ctx, in, out);
        m_samples[s] = (get_ns() - t0) / (double)micro_iters;

        int len = 0;
        t0 = get_ns();
        for (int i = 0; i < micro_iters; i++)
            EVP_EncryptUpdate(ecb_enc_ctx, out, &len, in, 16);
        g_samples[s] = (get_ns() - t0) / (double)micro_iters;
    }
    compute_stats(m_samples, 7, &st_m);
    compute_stats(g_samples, 7, &st_g);
    print_bench_row("aes128_encrypt_blk", &st_m, &st_g);
    EVP_CIPHER_CTX_free(ecb_enc_ctx);

    EVP_CIPHER_CTX *ecb_dec_ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ecb_dec_ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ecb_dec_ctx, 0);

    for (int s = 0; s < 7; s++)
    {
        double t0 = get_ns();
        for (int i = 0; i < micro_iters; i++)
            aes128_decrypt_block(&ctx, out, in);
        m_samples[s] = (get_ns() - t0) / (double)micro_iters;

        int len = 0;
        t0 = get_ns();
        for (int i = 0; i < micro_iters; i++)
            EVP_DecryptUpdate(ecb_dec_ctx, in, &len, out, 16);
        g_samples[s] = (get_ns() - t0) / (double)micro_iters;
    }
    compute_stats(m_samples, 7, &st_m);
    compute_stats(g_samples, 7, &st_g);
    print_bench_row("aes128_decrypt_blk", &st_m, &st_g);
    EVP_CIPHER_CTX_free(ecb_dec_ctx);

    // ------------------------------------------------------------------------
    // 3. CBC PKCS#7: Short Payload (64 Bytes) - Encrypt & Decrypt
    // ------------------------------------------------------------------------
    const int s64_bytes = 64;
    uint8_t s64_in[64], s64_out[80], s64_dec[80];
    for (int i = 0; i < s64_bytes; i++)
        s64_in[i] = (uint8_t)(rand() & 0xFF);

    EVP_CIPHER_CTX *cbc_s64_enc_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(cbc_s64_enc_ctx, EVP_aes_128_cbc(), NULL, key, iv);
    const int iters_64 = 20000;

    for (int s = 0; s < 7; s++)
    {
        double t0 = get_ns();
        for (int i = 0; i < iters_64; i++)
            aes128_cbc_encrypt_pkcs7(&ctx, iv, s64_in, (size_t)s64_bytes, s64_out);
        m_samples[s] = (get_ns() - t0) / (double)iters_64;

        int len = 0, fin_len = 0;
        t0 = get_ns();
        for (int i = 0; i < iters_64; i++)
        {
            EVP_EncryptInit_ex(cbc_s64_enc_ctx, NULL, NULL, NULL, iv);
            EVP_EncryptUpdate(cbc_s64_enc_ctx, s64_out, &len, s64_in, s64_bytes);
            EVP_EncryptFinal_ex(cbc_s64_enc_ctx, s64_out + len, &fin_len);
        }
        g_samples[s] = (get_ns() - t0) / (double)iters_64;
    }
    compute_stats(m_samples, 7, &st_m);
    compute_stats(g_samples, 7, &st_g);
    print_bench_row("aes128_cbc_64B_enc", &st_m, &st_g);
    EVP_CIPHER_CTX_free(cbc_s64_enc_ctx);

    size_t s64_ct_len = aes128_cbc_encrypt_pkcs7(&ctx, iv, s64_in, (size_t)s64_bytes, s64_out);
    EVP_CIPHER_CTX *cbc_s64_dec_ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(cbc_s64_dec_ctx, EVP_aes_128_cbc(), NULL, key, iv);

    for (int s = 0; s < 7; s++)
    {
        size_t dec_bytes = 0;
        double t0 = get_ns();
        for (int i = 0; i < iters_64; i++)
            aes128_cbc_decrypt_pkcs7(&ctx, iv, s64_out, s64_ct_len, s64_dec, &dec_bytes);
        m_samples[s] = (get_ns() - t0) / (double)iters_64;

        int len = 0, fin_len = 0;
        t0 = get_ns();
        for (int i = 0; i < iters_64; i++)
        {
            EVP_DecryptInit_ex(cbc_s64_dec_ctx, NULL, NULL, NULL, iv);
            EVP_DecryptUpdate(cbc_s64_dec_ctx, s64_dec, &len, s64_out, (int)s64_ct_len);
            EVP_DecryptFinal_ex(cbc_s64_dec_ctx, s64_dec + len, &fin_len);
        }
        g_samples[s] = (get_ns() - t0) / (double)iters_64;
    }
    compute_stats(m_samples, 7, &st_m);
    compute_stats(g_samples, 7, &st_g);
    print_bench_row("aes128_cbc_64B_dec", &st_m, &st_g);
    EVP_CIPHER_CTX_free(cbc_s64_dec_ctx);

    // ------------------------------------------------------------------------
    // 4. CBC PKCS#7: Medium Stream (1 KB) - Encrypt & Decrypt
    // ------------------------------------------------------------------------
    const int s1k_bytes = 1024;
    uint8_t *s1k_in = (uint8_t *)malloc(s1k_bytes);
    uint8_t *s1k_out = (uint8_t *)malloc(s1k_bytes + 16);
    uint8_t *s1k_dec = (uint8_t *)malloc(s1k_bytes + 16);
    for (int i = 0; i < s1k_bytes; i++)
        s1k_in[i] = (uint8_t)(rand() & 0xFF);

    EVP_CIPHER_CTX *cbc_1k_enc_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(cbc_1k_enc_ctx, EVP_aes_128_cbc(), NULL, key, iv);
    const int iters_1k = 10000;

    for (int s = 0; s < 7; s++)
    {
        double t0 = get_ns();
        for (int i = 0; i < iters_1k; i++)
            aes128_cbc_encrypt_pkcs7(&ctx, iv, s1k_in, (size_t)s1k_bytes, s1k_out);
        m_samples[s] = (get_ns() - t0) / (double)iters_1k;

        int len = 0, fin_len = 0;
        t0 = get_ns();
        for (int i = 0; i < iters_1k; i++)
        {
            EVP_EncryptInit_ex(cbc_1k_enc_ctx, NULL, NULL, NULL, iv);
            EVP_EncryptUpdate(cbc_1k_enc_ctx, s1k_out, &len, s1k_in, s1k_bytes);
            EVP_EncryptFinal_ex(cbc_1k_enc_ctx, s1k_out + len, &fin_len);
        }
        g_samples[s] = (get_ns() - t0) / (double)iters_1k;
    }
    compute_stats(m_samples, 7, &st_m);
    compute_stats(g_samples, 7, &st_g);
    print_bench_row("aes128_cbc_1KB_enc", &st_m, &st_g);
    EVP_CIPHER_CTX_free(cbc_1k_enc_ctx);

    size_t s1k_ct_len = aes128_cbc_encrypt_pkcs7(&ctx, iv, s1k_in, (size_t)s1k_bytes, s1k_out);
    EVP_CIPHER_CTX *cbc_1k_dec_ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(cbc_1k_dec_ctx, EVP_aes_128_cbc(), NULL, key, iv);

    for (int s = 0; s < 7; s++)
    {
        size_t dec_bytes = 0;
        double t0 = get_ns();
        for (int i = 0; i < iters_1k; i++)
            aes128_cbc_decrypt_pkcs7(&ctx, iv, s1k_out, s1k_ct_len, s1k_dec, &dec_bytes);
        m_samples[s] = (get_ns() - t0) / (double)iters_1k;

        int len = 0, fin_len = 0;
        t0 = get_ns();
        for (int i = 0; i < iters_1k; i++)
        {
            EVP_DecryptInit_ex(cbc_1k_dec_ctx, NULL, NULL, NULL, iv);
            EVP_DecryptUpdate(cbc_1k_dec_ctx, s1k_dec, &len, s1k_out, (int)s1k_ct_len);
            EVP_DecryptFinal_ex(cbc_1k_dec_ctx, s1k_dec + len, &fin_len);
        }
        g_samples[s] = (get_ns() - t0) / (double)iters_1k;
    }
    compute_stats(m_samples, 7, &st_m);
    compute_stats(g_samples, 7, &st_g);
    print_bench_row("aes128_cbc_1KB_dec", &st_m, &st_g);
    EVP_CIPHER_CTX_free(cbc_1k_dec_ctx);

    free(s1k_in);
    free(s1k_out);
    free(s1k_dec);

    // ------------------------------------------------------------------------
    // 5. CBC PKCS#7: Bulk Stream (4 KB) - Encrypt & Decrypt
    // ------------------------------------------------------------------------
    const int stream_bytes = 4096;
    uint8_t *s_in = (uint8_t *)malloc(stream_bytes);
    uint8_t *s_out = (uint8_t *)malloc(stream_bytes + 16);
    uint8_t *s_dec = (uint8_t *)malloc(stream_bytes + 16);
    for (int i = 0; i < stream_bytes; i++)
        s_in[i] = (uint8_t)(rand() & 0xFF);

    EVP_CIPHER_CTX *cbc_enc_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(cbc_enc_ctx, EVP_aes_128_cbc(), NULL, key, iv);
    const int cbc_iters = 5000;

    for (int s = 0; s < 7; s++)
    {
        double t0 = get_ns();
        for (int i = 0; i < cbc_iters; i++)
            aes128_cbc_encrypt_pkcs7(&ctx, iv, s_in, (size_t)stream_bytes, s_out);
        m_samples[s] = (get_ns() - t0) / (double)cbc_iters;

        int len = 0, fin_len = 0;
        t0 = get_ns();
        for (int i = 0; i < cbc_iters; i++)
        {
            EVP_EncryptInit_ex(cbc_enc_ctx, NULL, NULL, NULL, iv);
            EVP_EncryptUpdate(cbc_enc_ctx, s_out, &len, s_in, stream_bytes);
            EVP_EncryptFinal_ex(cbc_enc_ctx, s_out + len, &fin_len);
        }
        g_samples[s] = (get_ns() - t0) / (double)cbc_iters;
    }
    compute_stats(m_samples, 7, &st_m);
    compute_stats(g_samples, 7, &st_g);
    print_bench_row("aes128_cbc_4KB_enc", &st_m, &st_g);
    EVP_CIPHER_CTX_free(cbc_enc_ctx);

    size_t padded_ct_len = aes128_cbc_encrypt_pkcs7(&ctx, iv, s_in, (size_t)stream_bytes, s_out);
    EVP_CIPHER_CTX *cbc_dec_ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(cbc_dec_ctx, EVP_aes_128_cbc(), NULL, key, iv);

    for (int s = 0; s < 7; s++)
    {
        size_t dec_bytes = 0;
        double t0 = get_ns();
        for (int i = 0; i < cbc_iters; i++)
            aes128_cbc_decrypt_pkcs7(&ctx, iv, s_out, padded_ct_len, s_dec, &dec_bytes);
        m_samples[s] = (get_ns() - t0) / (double)cbc_iters;

        int len = 0, fin_len = 0;
        t0 = get_ns();
        for (int i = 0; i < cbc_iters; i++)
        {
            EVP_DecryptInit_ex(cbc_dec_ctx, NULL, NULL, NULL, iv);
            EVP_DecryptUpdate(cbc_dec_ctx, s_dec, &len, s_out, (int)padded_ct_len);
            EVP_DecryptFinal_ex(cbc_dec_ctx, s_dec + len, &fin_len);
        }
        g_samples[s] = (get_ns() - t0) / (double)cbc_iters;
    }
    compute_stats(m_samples, 7, &st_m);
    compute_stats(g_samples, 7, &st_g);
    print_bench_row("aes128_cbc_4KB_dec", &st_m, &st_g);

    free(s_in);
    free(s_out);
    free(s_dec);
    EVP_CIPHER_CTX_free(cbc_dec_ctx);
}

// ============================================================================
// SUITE ENTRY POINT
// ============================================================================

int run_aes_tests(void)
{
    srand(1337);
    print_suite_header("AES-128 & CBC MODE COMPREHENSIVE SUITE", BRIGHT_BLUE);

    int fails = 0;
    fails += test_primitives_nist_fips197();
    fails += test_primitives_random_inversion(100);
    fails += test_key_expansion_nist();
    fails += test_block_vs_openssl(500);

    // CBC Testing - Explicit Separation
    fails += test_cbc_raw_encrypt_vs_openssl(200);
    fails += test_cbc_raw_decrypt_vs_openssl(200);
    fails += test_cbc_pkcs7_encrypt_vs_openssl(500);
    fails += test_cbc_pkcs7_decrypt_vs_openssl(500);
    fails += test_cbc_pkcs7_invalid_padding_oracle(500);

    print_suite_summary(fails);
    if (fails == 0)
    {
        bench_aes();
    }
    return fails;
}