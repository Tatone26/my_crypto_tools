#include "tests.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

// Forward declaration
bool int_div(mprec_int *q, mprec_int *r, const mprec_int *a, const mprec_int *b);

// GMP reference operations
static void gmp_op_div(mpz_t r, const mpz_t a, const mpz_t b) { mpz_tdiv_q(r, a, b); }
static void gmp_op_rem(mpz_t r, const mpz_t a, const mpz_t b) { mpz_tdiv_r(r, a, b); }

// Generic wrappers
static bool wrap_int_div(mprec_int *q, const mprec_int *a, const mprec_int *b)
{
    INTEGER_STACK_ALLOC(rem, 2048);
    return int_div(q, &rem, a, b);
}

static bool wrap_int_rem(mprec_int *r, const mprec_int *a, const mprec_int *b)
{
    return int_div(NULL, r, a, b);
}

// Registry: Enable or disable tests in one line
static const FuncEntry registry[] = {
    {"int_div_q", OP_BINARY, 500, 2000, (void *)wrap_int_div, (void *)gmp_op_div},
    {"int_div_r", OP_BINARY, 500, 2000, (void *)wrap_int_rem, (void *)gmp_op_rem},
};

static const int registry_count = sizeof(registry) / sizeof(registry[0]);

static int run_all_tests(void)
{
    int total_failures = 0;

    for (int i = 0; i < registry_count; i++)
    {
        const FuncEntry *e = &registry[i];
        printf(BADGE_RUN CYAN "%-14s vs GMP (%d runs)... " RESET, e->name, e->test_iters);
        fflush(stdout);

        int fails = 0;
        if (e->kind == OP_BINARY)
            fails = driver_fuzz_bin(e->name, e->test_iters, (bin_fn_t)e->fn, (gmp_bin_fn_t)e->gmp_fn);
        else if (e->kind == OP_TERNARY)
            fails = driver_fuzz_tern(e->name, e->test_iters, (tern_fn_t)e->fn, (gmp_tern_fn_t)e->gmp_fn);
        else if (e->kind == OP_SHIFT)
            fails = driver_fuzz_shift(e->name, e->test_iters, (shift_fn_t)e->fn, (gmp_shift_fn_t)e->gmp_fn);

        if (fails == 0)
            printf(BADGE_PASS "\n");
        else
            total_failures += fails;
    }
    return total_failures;
}

static void run_all_benchmarks(int bits)
{
    printf("\n  " BOLD MAGENTA "── Benchmark Profile: %d-bit Modulus ──" RESET "\n", bits);

    for (int i = 0; i < registry_count; i++)
    {
        const FuncEntry *e = &registry[i];
        double mprec_ns = 0, gmp_ns = 0;

        if (e->kind == OP_BINARY)
            driver_bench_bin((bin_fn_t)e->fn, (gmp_bin_fn_t)e->gmp_fn, bits, e->bench_iters, &mprec_ns, &gmp_ns);
        else if (e->kind == OP_TERNARY)
            driver_bench_tern((tern_fn_t)e->fn, (gmp_tern_fn_t)e->gmp_fn, bits, e->bench_iters, &mprec_ns, &gmp_ns);
        else if (e->kind == OP_SHIFT)
            driver_bench_shift((shift_fn_t)e->fn, (gmp_shift_fn_t)e->gmp_fn, bits, e->bench_iters, &mprec_ns, &gmp_ns);

        double factor = mprec_ns / (gmp_ns > 0.0 ? gmp_ns : 1.0);
        printf("  " BADGE_BENCH "%-16s" WHITE "│ mprec: " BOLD CYAN "%8.1f ns" RESET WHITE " │ GMP: " BRIGHT_PURPLE "%8.1f ns" RESET WHITE " │ Factor: " BOLD BRIGHT_YELLOW "%.2fx" RESET "\n",
               e->name, mprec_ns, gmp_ns, factor);
    }
}

int run_mprec_adv_tests(void)
{
    srand(42);

    printf("\n" BRIGHT_PURPLE "┌────────────────────────────────────────────────────────┐\n" RESET);
    printf(BRIGHT_PURPLE "│" BOLD BRIGHT_WHITE "          MPREC_ADV MODULAR & DIV BENCHMARK             " RESET BRIGHT_PURPLE "│\n" RESET);
    printf(BRIGHT_PURPLE "└────────────────────────────────────────────────────────┘\n\n" RESET);

    int total_fails = run_all_tests();

    if (total_fails == 0)
    {
        printf("\n" BADGE_PASS BOLD GREEN "All configured suites passed successfully!" RESET "\n");
        run_all_benchmarks(256);
        run_all_benchmarks(512);
    }
    else
    {
        printf("\n" BADGE_FAIL BOLD RED "Benchmarks skipped due to %d failing test suite(s)." RESET "\n", total_fails);
    }

    return total_fails;
}