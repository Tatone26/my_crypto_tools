#include "tests.h"

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
    return int_mul_add(r, a, b, c) != (uint64_t)-1;
}
static bool wrap_int_lshift(mprec_int *r, const mprec_int *a, int shift) { return int_lshift(r, a, shift) != (uint64_t)-1; }
static bool wrap_int_rshift(mprec_int *r, const mprec_int *a, int shift) { return int_rshift(r, a, shift) != (uint64_t)-1; }

static const FuncEntry core_registry[] = {
    {"int_add", OP_BINARY, 50000, 1000000, (void *)wrap_int_add, (void *)gmp_op_add},
    {"int_sub", OP_BINARY, 50000, 1000000, (void *)wrap_int_sub, (void *)gmp_op_sub},
    {"int_lshift", OP_SHIFT, 50000, 1000000, (void *)wrap_int_lshift, (void *)gmp_op_lshift},
    {"int_rshift", OP_SHIFT, 50000, 1000000, (void *)wrap_int_rshift, (void *)gmp_op_rshift},
    {"int_mul_add", OP_TERNARY, 10000, 25000, (void *)wrap_int_mul_add, (void *)gmp_op_mul_add},
};
static const int core_registry_count = sizeof(core_registry) / sizeof(core_registry[0]);

static int test_io_parsers(int iterations)
{
    printf(BADGE_RUN CYAN "%-20s vs GMP (%d runs)... " RESET, "I/O Round-trip", iterations);
    fflush(stdout);

    mpz_t g_orig, g_check;
    mpz_inits(g_orig, g_check, NULL);
    INTEGER_STACK_ALLOC(orig, 512);
    INTEGER_STACK_ALLOC(from_hex, 512);
    INTEGER_STACK_ALLOC(from_dec, 512);

    char hex_buf[512], dec_buf[1024];
    int fails = 0;

    for (int i = 0; i < iterations; i++)
    {
        fill_random(&orig);
        mprec_to_gmp(g_orig, &orig);

        if (sprint_hex(&orig, hex_buf, sizeof(hex_buf)) < 0 || !integer_from_hex(&from_hex, hex_buf) || int_cmp(&orig, &from_hex) != 0 ||
            sprint_dec(&orig, dec_buf, sizeof(dec_buf)) < 0 || !integer_from_dec(&from_dec, dec_buf) || int_cmp(&orig, &from_dec) != 0)
        {
            fails++;
            break;
        }

        mpz_set_str(g_check, dec_buf, 10);
        if (mpz_cmp(g_orig, g_check) != 0)
        {
            fails++;
            break;
        }
    }

    mpz_clears(g_orig, g_check, NULL);
    if (fails == 0)
        printf(BADGE_PASS "\n");
    else
        printf(BADGE_FAIL "\n");
    return fails;
}

static int test_cmp_and_bits(int iterations)
{
    printf(BADGE_RUN CYAN "%-20s vs GMP (%d runs)... " RESET, "cmp & bit operations", iterations);
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
        if (((m_cmp > 0) - (m_cmp < 0)) != ((g_cmp > 0) - (g_cmp < 0)) ||
            int_bit_length(&a) != (uint64_t)mpz_sizeinbase(ga, 2))
        {
            fails++;
            break;
        }

        int bit_idx = rand() % 512;
        if (int_bit_check(&a, bit_idx) != (bool)mpz_tstbit(ga, bit_idx))
        {
            fails++;
            break;
        }

        bool target_val = (rand() % 2) != 0;
        int_bit_set(&a, bit_idx, target_val);
        if (target_val)
            mpz_setbit(ga, bit_idx);
        else
            mpz_clrbit(ga, bit_idx);

        if (!gmp_equals_mprec(ga, &a))
        {
            fails++;
            break;
        }
    }

    mpz_clears(ga, gb, NULL);
    if (fails == 0)
        printf(BADGE_PASS "\n");
    else
        printf(BADGE_FAIL "\n");
    return fails;
}

static void bench_micro_ops(int bits, int iters)
{
    INTEGER_STACK_ALLOC(a, bits);
    INTEGER_STACK_ALLOC(b, bits);
    random_number(&a, bits);
    random_number(&b, bits);

    mpz_t ga, gb;
    mpz_inits(ga, gb, NULL);
    mprec_to_gmp(ga, &a);
    mprec_to_gmp(gb, &b);

    double m_samples[7], g_samples[7];
    BenchStats st_m = {0}, st_g = {0};

    // 1. int_cmp
    for (int s = 0; s < 7; s++)
    {
        random_number(&a, bits);
        random_number(&b, bits);
        mprec_to_gmp(ga, &a);
        mprec_to_gmp(gb, &b);

        volatile int dummy = 0;
        double t0 = get_ns();
        for (int i = 0; i < iters; i++)
            dummy += int_cmp(&a, &b);
        m_samples[s] = (get_ns() - t0) / (double)iters;

        t0 = get_ns();
        for (int i = 0; i < iters; i++)
            dummy += mpz_cmp(ga, gb);
        g_samples[s] = (get_ns() - t0) / (double)iters;
        (void)dummy;
    }
    compute_stats(m_samples, 7, &st_m);
    compute_stats(g_samples, 7, &st_g);
    print_bench_row("int_cmp", &st_m, &st_g);

    // 2. int_bit_length
    for (int s = 0; s < 7; s++)
    {
        random_number(&a, bits);
        mprec_to_gmp(ga, &a);

        volatile uint64_t dummy = 0;
        double t0 = get_ns();
        for (int i = 0; i < iters; i++)
            dummy += int_bit_length(&a);
        m_samples[s] = (get_ns() - t0) / (double)iters;

        t0 = get_ns();
        for (int i = 0; i < iters; i++)
            dummy += (uint64_t)mpz_sizeinbase(ga, 2);
        g_samples[s] = (get_ns() - t0) / (double)iters;
        (void)dummy;
    }
    compute_stats(m_samples, 7, &st_m);
    compute_stats(g_samples, 7, &st_g);
    print_bench_row("int_bit_length", &st_m, &st_g);

    mpz_clears(ga, gb, NULL);
}

int run_mprec_core_tests(void)
{
    srand(1337);
    print_suite_header("MPREC_CORE VERIFICATION & RACE", BRIGHT_CYAN);

    int fails = test_io_parsers(5000);
    fails += test_cmp_and_bits(50000);
    fails += run_registry_tests(core_registry, core_registry_count);

    print_suite_summary(fails);
    if (fails == 0)
    {
        for (int bits = 256; bits <= 2048; bits *= 2)
        {
            print_bench_header(bits, "GMP");
            bench_micro_ops(bits, 1000000);
            run_registry_benchmarks(core_registry, core_registry_count, bits, "GMP");
        }
    }
    return fails;
}