#ifndef TESTS_H
#define TESTS_H

#include "colors.h"
#include "integers.h"
#include "crypto.h"
#include <gmp.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// Core Function Signatures
typedef bool (*bin_fn_t)(mprec_int *r, const mprec_int *a, const mprec_int *b);
typedef void (*gmp_bin_fn_t)(mpz_t gr, const mpz_t ga, const mpz_t gb);

typedef bool (*tern_fn_t)(mprec_int *r, const mprec_int *a, const mprec_int *b, const mprec_int *n);
typedef void (*gmp_tern_fn_t)(mpz_t gr, const mpz_t ga, const mpz_t gb, const mpz_t gn);

typedef bool (*shift_fn_t)(mprec_int *r, const mprec_int *a, int shift);
typedef void (*gmp_shift_fn_t)(mpz_t gr, const mpz_t ga, mp_bitcnt_t shift);

typedef enum
{
    OP_BINARY,
    OP_TERNARY,
    OP_SHIFT
} OpKind;

typedef struct
{
    const char *name;
    OpKind kind;
    int test_iters;
    int bench_iters;
    void *fn;
    void *gmp_fn;
} FuncEntry;

// Generic Test Drivers
int driver_fuzz_bin(const char *name, int iters, bin_fn_t fn, gmp_bin_fn_t gmp_fn);
int driver_fuzz_tern(const char *name, int iters, tern_fn_t fn, gmp_tern_fn_t gmp_fn);
int driver_fuzz_shift(const char *name, int iters, shift_fn_t fn, gmp_shift_fn_t gmp_fn);

// Generic Benchmark Drivers
void driver_bench_bin(bin_fn_t fn, gmp_bin_fn_t gmp_fn, int bits, int iters, double *mprec_ns, double *gmp_ns);
void driver_bench_tern(tern_fn_t fn, gmp_tern_fn_t gmp_fn, int bits, int iters, double *mprec_ns, double *gmp_ns);
void driver_bench_shift(shift_fn_t fn, gmp_shift_fn_t gmp_fn, int bits, int iters, double *mprec_ns, double *gmp_ns);

static inline void mprec_to_gmp(mpz_t g, const mprec_int *m)
{
    mpz_import(g, m->size, -1, 8, 0, 0, m->d);
}

static inline double get_ns(void)
{
    return ((double)clock() / CLOCKS_PER_SEC) * 1e9;
}

bool gmp_equals_mprec(const mpz_t g, const mprec_int *m);

inline void fill_random(mprec_int *m)
{
    random_number(m, m->size);
}

#endif // TESTS_H