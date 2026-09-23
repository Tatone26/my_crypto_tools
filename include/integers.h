#ifndef INTEGERS_H
#define INTEGERS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

// returns the number of 64 bits blocks for a given bit size.
#define NB_BLOCKS(bits) (((bits) + 63) / 64)

#define NB_BITS(blocks) ((blocks) * 64)

/// @brief Main structure for multiprecision integers
typedef struct
{
    uint64_t *d; // blocks of 64 bits
    int size;    // number of blocks
} mprec_int;

/// Allows easy stack definition of an integer.
#define INTEGER_STACK_ALLOC(name, bits)      \
    uint64_t name##_blocks[NB_BLOCKS(bits)]; \
    mprec_int name = {                       \
        .d = name##_blocks,                  \
        .size = NB_BLOCKS(bits)}

#define U64_TO_MPREC(name, number)          \
    uint64_t name##_blocks[1] = {(number)}; \
    mprec_int name = {                      \
        .d = name##_blocks,                 \
        .size = 1}

int int_cmp(const mprec_int *a, const mprec_int *b);
uint64_t int_bit_length(const mprec_int *a);
bool int_bit_check(const mprec_int *a, const uint64_t k);
void int_bit_set(mprec_int *a, const uint64_t k, bool value);
uint64_t int_add(mprec_int *r, const mprec_int *a, const mprec_int *b);
uint64_t int_sub(mprec_int *r, const mprec_int *a, const mprec_int *b);
uint64_t int_lshift(mprec_int *r, const mprec_int *a, const int k);
uint64_t int_rshift(mprec_int *r, const mprec_int *a, const int k);
uint64_t int_mul_add(mprec_int *r, const mprec_int *a, const mprec_int *b, const mprec_int *c);

bool integer_from_hex(mprec_int *mem, const char *hex);
void print_dec(const mprec_int *integer, FILE *output);
int sprint_dec(const mprec_int *integer, char *buf, size_t buf_size);
void print_hex(const mprec_int *integer, FILE *output);
int sprint_hex(const mprec_int *integer, char *buf, size_t buf_size);
bool integer_from_dec(mprec_int *mem, const char *dec);

bool int_div(mprec_int *q, mprec_int *r, const mprec_int *a, const mprec_int *b);

#endif