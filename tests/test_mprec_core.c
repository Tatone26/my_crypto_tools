#include "tests.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

// ============================================================================
// GMP AND MPREC WRAPPERS
// ============================================================================

static void gmp_op_add(mpz_t r, const mpz_t a, const mpz_t b) { mpz_add(r, a, b); }
static void gmp_op_sub(mpz_t r, const mpz_t a, const mpz_t b) { mpz_sub(r, a, b); }
static void gmp_op_lshift(mpz_t r, const mpz_t a, mp_bitcnt_t s) { mpz_mul_2exp(r, a, s); }
static void gmp_op_rshift(mpz_t r, const mpz_t a, mp_bitcnt_t s) { mpz_fdiv_q_2exp(r, a, s); }

static void gmp_op_mul_add(mpz_t r, const mpz_t a, const mpz_t b, const mpz_t c)
{
    mpz_mul(r, a, b);
    mpz_add(r, r, c);
}

static bool wrap_int_add(mprec_int *r, const mprec_int *a, const mprec_int *b)
{
    int_add(r, a, b);
    return true;
}

static bool wrap_int_sub(mprec_int *r, const mprec_int *a, const mprec_int *b)
{
    if (int_cmp(a, b) < 0)
        int_sub(r, b, a);
    else
        int_sub(r, a, b);
    return true;
}

static bool wrap_int_mul_add(mprec_int *r, const mprec_int *a, const mprec_int *b, const mprec_int *c)
{
    uint64_t err = int_mul_add(r, a, b, c);
    return err != (uint64_t)-1;
}

static bool wrap_int_lshift(mprec_int *r, const mprec_int *a, int shift)
{
    uint64_t err = int_lshift(r, a, shift);
    return err != (uint64_t)-1;
}

static bool wrap_int_rshift(mprec_int *r, const mprec_int *a, int shift)
{
    uint64_t err = int_rshift(r, a, shift);
    return err != (uint64_t)-1;
}

// ============================================================================
// SPECIALIZED TESTS (I/O, Bits & Comparisons)
// ============================================================================

static int test_io_parsers(int iterations)
{
    printf(BADGE_RUN CYAN "%-14s vs GMP (%d runs)... " RESET, "I/O Round-trip", iterations);
    fflush(stdout);

    mpz_t g_orig, g_check;
    mpz_inits(g_orig, g_check, NULL);

    INTEGER_STACK_ALLOC(orig, 512);
    INTEGER_STACK_ALLOC(from_hex, 512);
    INTEGER_STACK_ALLOC(from_dec, 512);

    char hex_buf[512];
    char dec_buf[1024];
    int fails = 0;

    for (int i = 0; i < iterations; i++)
    {
        fill_random(&orig);
        mprec_to_gmp(g_orig, &orig);

        if (sprint_hex(&orig, hex_buf, sizeof(hex_buf)) < 0 || !integer_from_hex(&from_hex, hex_buf) || int_cmp(&orig, &from_hex) != 0)
        {
            printf("\n" BADGE_FAIL "Hex round-trip mismatch!\n");
            fails++;
            break;
        }

        if (sprint_dec(&orig, dec_buf, sizeof(dec_buf)) < 0 || !integer_from_dec(&from_dec, dec_buf) || int_cmp(&orig, &from_dec) != 0)
        {
            printf("\n" BADGE_FAIL "Dec round-trip mismatch!\n");
            fails++;
            break;
        }

        mpz_set_str(g_check, dec_buf, 10);
        if (mpz_cmp(g_orig, g_check) != 0)
        {
            printf("\n" BADGE_FAIL "sprint_dec vs GMP oracle mismatch!\n");
            fails++;
            break;
        }
    }

    mpz_clears(g_orig, g_check, NULL);
    if (fails == 0)
        printf(BADGE_PASS "\n");
    return fails;
}

static int test_cmp_and_bits(int iterations)
{
    printf(BADGE_RUN CYAN "%-14s vs GMP (%d runs)... " RESET, "cmp & bits", iterations);
    fflush(stdout);

    mpz_t ga, gb;
    mpz_inits(ga, gb, NULL);

    INTEGER_STACK_ALLOC(a, 512);
    INTEGER_STACK_ALLOC(b, 512);

    int fails = 0;
    for (int i = 0; i < iterations; i++)
    {
        fill_random(&a);
        fill_random(&b);
        mprec_to_gmp(ga, &a);
        mprec_to_gmp(gb, &b);

        int m_cmp = int_cmp(&a, &b);
        int g_cmp = mpz_cmp(ga, gb);
        if (((m_cmp > 0) - (m_cmp < 0)) != ((g_cmp > 0) - (g_cmp < 0)))
        {
            printf("\n" BADGE_FAIL "int_cmp mismatch!\n");
            fails++;
            break;
        }

        if (int_bit_length(&a) != (uint64_t)mpz_sizeinbase(ga, 2))
        {
            printf("\n" BADGE_FAIL "int_bit_length mismatch!\n");
            fails++;
            break;
        }

        int bit_idx = rand() % 512;
        if (int_bit_check(&a, bit_idx) != (bool)mpz_tstbit(ga, bit_idx))
        {
            printf("\n" BADGE_FAIL "int_bit_check mismatch!\n");
            fails++;
            break;
        }

        // Test int_bit_set
        bool target_val = (rand() % 2) != 0;
        int_bit_set(&a, bit_idx, target_val);
        if (target_val)
            mpz_setbit(ga, bit_idx);
        else
            mpz_clrbit(ga, bit_idx);

        if (!gmp_equals_mprec(ga, &a))
        {
            printf("\n" BADGE_FAIL "int_bit_set mismatch!\n");
            fails++;
            break;
        }
    }

    mpz_clears(ga, gb, NULL);
    if (fails == 0)
        printf(BADGE_PASS "\n");
    return fails;
}

// ============================================================================
// MODULAR REGISTRY (ARITHMETIC & SHIFTS)
// ============================================================================

static const FuncEntry core_registry[] = {
    {"int_add", OP_BINARY, 50000, 1000000, (void *)wrap_int_add, (void *)gmp_op_add},
    {"int_sub", OP_BINARY, 50000, 1000000, (void *)wrap_int_sub, (void *)gmp_op_sub},
    {"int_lshift", OP_SHIFT, 50000, 1000000, (void *)wrap_int_lshift, (void *)gmp_op_lshift},
    {"int_rshift", OP_SHIFT, 50000, 1000000, (void *)wrap_int_rshift, (void *)gmp_op_rshift},
    {"int_mul_add", OP_TERNARY, 10000, 100000, (void *)wrap_int_mul_add, (void *)gmp_op_mul_add},
};

static const int core_registry_count = sizeof(core_registry) / sizeof(core_registry[0]);

// ============================================================================
// DEDICATED BENCHMARKS FOR UNARY & BIT MANIPULATIONS
// ============================================================================

static inline void print_bench_row(const char *name, double mprec_ns, double gmp_ns)
{
    double factor = mprec_ns / (gmp_ns > 0.0 ? gmp_ns : 1.0);
    printf("  " BADGE_BENCH "%-16s" WHITE "│ mprec: " BOLD CYAN "%8.1f ns" RESET WHITE " │ GMP: " BRIGHT_PURPLE "%8.1f ns" RESET WHITE " │ Factor: " BOLD BRIGHT_YELLOW "%.2fx" RESET "\n",
           name, mprec_ns, gmp_ns, factor);
}

static void bench_cmp(int bits, int iters)
{
    INTEGER_STACK_ALLOC(a, bits);
    INTEGER_STACK_ALLOC(b, bits);
    fill_random(&a);
    fill_random(&b);

    mpz_t ga, gb;
    mpz_inits(ga, gb, NULL);
    mprec_to_gmp(ga, &a);
    mprec_to_gmp(gb, &b);

    volatile int dummy = 0;

    double t0 = get_ns();
    for (int i = 0; i < iters; i++)
        dummy += int_cmp(&a, &b);
    double mprec_ns = (get_ns() - t0) / iters;

    t0 = get_ns();
    for (int i = 0; i < iters; i++)
        dummy += mpz_cmp(ga, gb);
    double gmp_ns = (get_ns() - t0) / iters;

    (void)dummy;
    mpz_clears(ga, gb, NULL);
    print_bench_row("int_cmp", mprec_ns, gmp_ns);
}

static void bench_bit_length(int bits, int iters)
{
    INTEGER_STACK_ALLOC(a, bits);
    fill_random(&a);

    mpz_t ga;
    mpz_init(ga);
    mprec_to_gmp(ga, &a);

    volatile uint64_t dummy = 0;

    double t0 = get_ns();
    for (int i = 0; i < iters; i++)
        dummy += int_bit_length(&a);
    double mprec_ns = (get_ns() - t0) / iters;

    t0 = get_ns();
    for (int i = 0; i < iters; i++)
        dummy += (uint64_t)mpz_sizeinbase(ga, 2);
    double gmp_ns = (get_ns() - t0) / iters;

    (void)dummy;
    mpz_clear(ga);
    print_bench_row("int_bit_length", mprec_ns, gmp_ns);
}

static void bench_bit_check(int bits, int iters)
{
    INTEGER_STACK_ALLOC(a, bits);
    fill_random(&a);

    mpz_t ga;
    mpz_init(ga);
    mprec_to_gmp(ga, &a);

    uint64_t target_bit = (uint64_t)(bits / 2 + 13);
    volatile bool dummy = false;

    double t0 = get_ns();
    for (int i = 0; i < iters; i++)
        dummy ^= int_bit_check(&a, target_bit);
    double mprec_ns = (get_ns() - t0) / iters;

    t0 = get_ns();
    for (int i = 0; i < iters; i++)
        dummy ^= (bool)mpz_tstbit(ga, target_bit);
    double gmp_ns = (get_ns() - t0) / iters;

    (void)dummy;
    mpz_clear(ga);
    print_bench_row("int_bit_check", mprec_ns, gmp_ns);
}

static void bench_bit_set(int bits, int iters)
{
    INTEGER_STACK_ALLOC(a, bits);
    fill_random(&a);

    mpz_t ga;
    mpz_init(ga);
    mprec_to_gmp(ga, &a);

    uint64_t target_bit = (uint64_t)(bits / 2 + 13);

    double t0 = get_ns();
    for (int i = 0; i < iters; i++)
        int_bit_set(&a, target_bit, (i & 1));
    double mprec_ns = (get_ns() - t0) / iters;

    t0 = get_ns();
    for (int i = 0; i < iters; i++)
    {
        if (i & 1)
            mpz_setbit(ga, target_bit);
        else
            mpz_clrbit(ga, target_bit);
    }
    double gmp_ns = (get_ns() - t0) / iters;

    mpz_clear(ga);
    print_bench_row("int_bit_set", mprec_ns, gmp_ns);
}

// ============================================================================
// RUNNERS
// ============================================================================

static int run_core_tests(void)
{
    int total_failures = 0;
    total_failures += test_io_parsers(5000);
    total_failures += test_cmp_and_bits(50000);

    for (int i = 0; i < core_registry_count; i++)
    {
        const FuncEntry *e = &core_registry[i];
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

static void run_core_benchmarks(int bits)
{
    printf("\n  " BOLD MAGENTA "── Benchmark Profile: %d-bit ──" RESET "\n", bits);

    // 1. Bitwise and Comparison Operations
    int micro_iters = 1000000;
    bench_cmp(bits, micro_iters);
    bench_bit_length(bits, micro_iters);
    bench_bit_check(bits, micro_iters);
    bench_bit_set(bits, micro_iters);

    // 2. Arithmetic and Shift Operations from Registry
    for (int i = 0; i < core_registry_count; i++)
    {
        const FuncEntry *e = &core_registry[i];
        double mprec_ns = 0, gmp_ns = 0;

        if (e->kind == OP_BINARY)
            driver_bench_bin((bin_fn_t)e->fn, (gmp_bin_fn_t)e->gmp_fn, bits, e->bench_iters, &mprec_ns, &gmp_ns);
        else if (e->kind == OP_TERNARY)
            driver_bench_tern((tern_fn_t)e->fn, (gmp_tern_fn_t)e->gmp_fn, bits, e->bench_iters / 4, &mprec_ns, &gmp_ns);
        else if (e->kind == OP_SHIFT)
            driver_bench_shift((shift_fn_t)e->fn, (gmp_shift_fn_t)e->gmp_fn, bits, e->bench_iters, &mprec_ns, &gmp_ns);

        print_bench_row(e->name, mprec_ns, gmp_ns);
    }
}

int run_mprec_core_tests(void)
{
    srand(1337);

    printf("\n" BRIGHT_CYAN "┌────────────────────────────────────────────────────────┐\n" RESET);
    printf(BRIGHT_CYAN "│" BOLD BRIGHT_WHITE "             MPREC_CORE VERIFICATION & RACE             " RESET BRIGHT_CYAN "│\n" RESET);
    printf(BRIGHT_CYAN "└────────────────────────────────────────────────────────┘\n\n" RESET);

    int total_fails = run_core_tests();

    if (total_fails == 0)
    {
        printf("\n" BADGE_PASS BOLD GREEN "All core suites passed successfully!" RESET "\n");
        run_core_benchmarks(256);
        run_core_benchmarks(1024);
        run_core_benchmarks(2048);
    }
    else
    {
        printf("\n" BADGE_FAIL BOLD RED "Core benchmarks skipped due to failures." RESET "\n");
    }

    return total_fails;
}