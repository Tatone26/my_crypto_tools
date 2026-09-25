#ifndef TESTS_H
#define TESTS_H

#include "colors.h"
#include "integers.h"
#include "crypto.h"
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>

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

// Statistical Result Container
typedef struct
{
    double mean_ns;
    double stddev_ns;
    double min_ns;
} BenchStats;

// Statistical Calculation Utility
void compute_stats(const double *samples, int count, BenchStats *out);

// Generic Test Drivers
int driver_fuzz_bin(const char *name, int iters, bin_fn_t fn, gmp_bin_fn_t gmp_fn);
int driver_fuzz_tern(const char *name, int iters, tern_fn_t fn, gmp_tern_fn_t gmp_fn);
int driver_fuzz_shift(const char *name, int iters, shift_fn_t fn, gmp_shift_fn_t gmp_fn);

// Generic Benchmark Drivers with Multi-Sample Statistics
void driver_bench_bin(bin_fn_t fn, gmp_bin_fn_t gmp_fn, int bits, int iters, BenchStats *mprec_st, BenchStats *gmp_st);
void driver_bench_tern(tern_fn_t fn, gmp_tern_fn_t gmp_fn, int bits, int iters, BenchStats *mprec_st, BenchStats *gmp_st);
void driver_bench_shift(shift_fn_t fn, gmp_shift_fn_t gmp_fn, int bits, int iters, BenchStats *mprec_st, BenchStats *gmp_st);

// Diagnostic & UI Printing
void print_diag_hex(const char *label, const mprec_int *m);
void print_suite_header(const char *title, const char *color);
void print_bench_header(int bits, const char *oracle_name);
void print_bench_row(const char *name, const BenchStats *mprec_st, const BenchStats *gmp_st);
void print_suite_summary(int total_fails);

// Generic Registry Runners
int run_registry_tests(const FuncEntry *registry, int count);
void run_registry_benchmarks(const FuncEntry *registry, int count, int bits, const char *adv_name);

// Timing & Conversion
static inline void mprec_to_gmp(mpz_t g, const mprec_int *m)
{
    mpz_import(g, m->size, -1, 8, 0, 0, m->d);
}

static inline double get_ns(void)
{
    return ((double)clock() / CLOCKS_PER_SEC) * 1e9;
}

bool gmp_equals_mprec(const mpz_t g, const mprec_int *m);

static inline void fill_random(mprec_int *m)
{
    random_number(m, m->size * 64);
}

// Suite Entry Points
int run_mprec_core_tests(void);
int run_mprec_adv_tests(void);
int run_mprec_eea_tests(void);
int run_random_tests(void);
int run_aes_tests(void);

#endif // TESTS_H