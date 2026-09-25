#include "tests.h"

void random_number(mprec_int *mem, int bits);
void random_odd_number(mprec_int *mem, int bits);
bool miller_rabin(mprec_int *num, int k);

static int test_random_invariants(int iterations)
{
    printf(BADGE_RUN CYAN "%-20s vs Invariants (%d runs)... " RESET, "Rand Invariants", iterations);
    fflush(stdout);

    INTEGER_STACK_ALLOC(r, 1024);
    int fails = 0;

    for (int i = 0; i < iterations; i++)
    {
        int target_bits = 2 + (rand() % 1022);
        random_number(&r, target_bits);
        if (int_bit_length(&r) != (uint64_t)target_bits)
        {
            fails++;
            break;
        }

        random_odd_number(&r, target_bits);
        if (int_bit_length(&r) != (uint64_t)target_bits || !int_bit_check(&r, 0))
        {
            fails++;
            break;
        }
    }

    if (fails == 0)
        printf(BADGE_PASS "\n");
    else
        printf(BADGE_FAIL "\n");
    return fails;
}

static int test_random_statistics(int total_samples)
{
    printf(BADGE_RUN CYAN "%-20s vs Chi²/Ratio (%d runs)... " RESET, "Rand Statistics", total_samples);
    fflush(stdout);

    INTEGER_STACK_ALLOC(r, 512);
    uint64_t total_bits = 0, set_bits = 0, byte_counts[256] = {0};

    for (int i = 0; i < total_samples; i++)
    {
        random_number(&r, 512);
        for (int b = 0; b < 511; b++)
        {
            total_bits++;
            if (int_bit_check(&r, b))
                set_bits++;
        }
        uint8_t *bytes = (uint8_t *)r.d;
        for (size_t j = 0; j < (512 / 8) - 1; j++)
            byte_counts[bytes[j]]++;
    }

    double bit_ratio = (double)set_bits / (double)total_bits;
    double expected_per_bucket = (double)(total_samples * ((512 / 8) - 1)) / 256.0;
    double chi_square = 0.0;
    for (int i = 0; i < 256; i++)
    {
        double diff = (double)byte_counts[i] - expected_per_bucket;
        chi_square += (diff * diff) / expected_per_bucket;
    }

    if (bit_ratio < 0.485 || bit_ratio > 0.515 || chi_square > 320.0)
    {
        printf(BADGE_FAIL "\n");
        return 1;
    }

    printf(BADGE_PASS "\n");
    return 0;
}

static int test_miller_rabin_forced_composites(int iterations)
{
    printf(BADGE_RUN CYAN "%-20s (%d forced composites)... " RESET, "MR False Positives", iterations);
    fflush(stdout);

    INTEGER_STACK_ALLOC(p, 512);
    INTEGER_STACK_ALLOC(q, 512);
    INTEGER_STACK_ALLOC(comp, 1024);

    for (int i = 0; i < iterations; i++)
    {
        random_odd_number(&p, 32 + (rand() % 96));
        random_odd_number(&q, 32 + (rand() % 96));
        p.d[0] |= 3ULL;
        q.d[0] |= 3ULL;

        int_mul_add(&comp, &p, &q, NULL);
        if (miller_rabin(&comp, 25))
        {
            printf(BADGE_FAIL "\n");
            return 1;
        }
    }

    printf(BADGE_PASS WHITE "(Filtered: " BOLD GREEN "100.0%%" RESET WHITE ")\n" RESET);
    return 0;
}

static int test_miller_rabin_accuracy_against_gmp(int iterations)
{
    printf(BADGE_RUN CYAN "%-20s vs GMP (%d odd candidates)... " RESET, "MR GMP Accuracy", iterations);
    fflush(stdout);

    INTEGER_STACK_ALLOC(cand, 512);
    mpz_t gcand;
    mpz_init(gcand);

    int matches = 0, primes_found = 0;
    for (int i = 0; i < iterations; i++)
    {
        random_odd_number(&cand, 32 + (rand() % 128));
        mprec_to_gmp(gcand, &cand);

        bool mprec_verdict = miller_rabin(&cand, 25);
        bool gmp_verdict = (mpz_probab_prime_p(gcand, 25) > 0);

        if (mprec_verdict == gmp_verdict)
        {
            matches++;
            if (mprec_verdict)
                primes_found++;
        }
        else
        {
            mpz_clear(gcand);
            printf(BADGE_FAIL "\n");
            return 1;
        }
    }

    mpz_clear(gcand);
    printf(BADGE_PASS WHITE "(Agreement: " BOLD GREEN "%.1f%%" RESET WHITE ", Primes: " BOLD CYAN "%d" RESET WHITE ")\n" RESET,
           ((double)matches / iterations) * 100.0, primes_found);
    return 0;
}

static void bench_random_suite(int bits)
{
    print_bench_header(bits, "GMP");
    INTEGER_STACK_ALLOC(r, bits);

    // 1. Random Number Gen
    BenchStats rand_m = {0}, rand_g = {0};
    double m_samples[7], g_samples[7];
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, 42);
    mpz_t gr;
    mpz_init(gr);

    for (int s = 0; s < 7; s++)
    {
        double t0 = get_ns();
        for (int i = 0; i < 5000; i++)
            random_number(&r, bits);
        m_samples[s] = (get_ns() - t0) / 5000;

        t0 = get_ns();
        for (int i = 0; i < 5000; i++)
            mpz_urandomb(gr, state, (mp_bitcnt_t)bits);
        g_samples[s] = (get_ns() - t0) / 5000;
    }
    compute_stats(m_samples, 7, &rand_m);
    compute_stats(g_samples, 7, &rand_g);
    print_bench_row("random_number", &rand_m, &rand_g);
    mpz_clear(gr);
    gmp_randclear(state);

    // 2. Miller-Rabin Primality
    BenchStats mr_m = {0}, mr_g = {0};
    mpz_init(gr);
    volatile bool dummy_m = false;
    volatile int dummy_g = 0;

    for (int s = 0; s < 7; s++)
    {
        random_odd_number(&r, bits);
        mprec_to_gmp(gr, &r);

        double t0 = get_ns();
        for (int i = 0; i < 20; i++)
            dummy_m ^= miller_rabin(&r, 25);
        m_samples[s] = (get_ns() - t0) / 20;

        t0 = get_ns();
        for (int i = 0; i < 20; i++)
            dummy_g += mpz_probab_prime_p(gr, 25);
        g_samples[s] = (get_ns() - t0) / 20;
    }
    (void)dummy_m;
    (void)dummy_g;
    mpz_clear(gr);

    compute_stats(m_samples, 7, &mr_m);
    compute_stats(g_samples, 7, &mr_g);
    print_bench_row("miller_rabin", &mr_m, &mr_g);
}

int run_random_tests(void)
{
    srand(1337);
    print_suite_header("CSPRNG & MILLER-RABIN VALIDATION", BRIGHT_CYAN);

    int fails = test_random_invariants(5000);
    fails += test_random_statistics(2000);
    fails += test_miller_rabin_forced_composites(500);
    fails += test_miller_rabin_accuracy_against_gmp(500);

    print_suite_summary(fails);
    if (fails == 0)
    {
        bench_random_suite(128);
        bench_random_suite(256);
        bench_random_suite(512);
    }
    return fails;
}