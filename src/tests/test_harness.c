#include "tests.h"
#include <string.h>
#include <math.h>

#define BENCH_SAMPLES 7

// ============================================================================
// STATISTICAL ACCUMULATOR
// ============================================================================

void compute_stats(const double *samples, int count, BenchStats *out)
{
    if (!out)
        return;

    if (count <= 0)
    {
        out->mean_ns = 0.0;
        out->stddev_ns = 0.0;
        out->min_ns = 0.0;
        return;
    }

    double sum = 0.0;
    double min_v = samples[0];

    for (int i = 0; i < count; i++)
    {
        sum += samples[i];
        if (samples[i] < min_v)
            min_v = samples[i];
    }

    double mean = sum / (double)count;
    double var_sum = 0.0;

    for (int i = 0; i < count; i++)
    {
        double diff = samples[i] - mean;
        var_sum += diff * diff;
    }

    double stddev = (count > 1) ? sqrt(var_sum / (double)(count - 1)) : 0.0;

    out->mean_ns = mean;
    out->stddev_ns = stddev;
    out->min_ns = min_v;
}

// ============================================================================
// UI & BANNER FORMATTING
// ============================================================================

void print_suite_header(const char *title, const char *color)
{
    printf("\n%s┌────────────────────────────────────────────────────────────────────────────────────────┐\n" RESET, color);
    printf("%s│" BOLD BRIGHT_WHITE " %-86s " RESET "%s│\n" RESET, color, title, color);
    printf("%s└────────────────────────────────────────────────────────────────────────────────────────┘\n\n" RESET, color);
}

void print_bench_header(int bits)
{
    printf("\n  " BOLD MAGENTA "── Benchmark Profile: %d-bit Operands ──" RESET "\n\n", bits);
    printf("  " BOLD WHITE "%-21s" RESET "│" BOLD CYAN "              mprec (ns)              " RESET "│" BRIGHT_PURPLE "               GMP (ns)               " RESET "│" BOLD YELLOW "   RATIO   " RESET "\n", "OPERATION");
    printf("                       │" CYAN "    Avg     │    Best    │     ±σ     " RESET "│" BRIGHT_PURPLE "    Avg     │    Best    │     ±σ     " RESET "│" YELLOW " (vs GMP)  " RESET "\n");
    printf(DIM BRIGHT_BLACK "  ─────────────────────┼────────────┼────────────┼────────────┼────────────┼────────────┼────────────┼───────────\n" RESET);
}

void print_bench_row(const char *name, const BenchStats *m, const BenchStats *g)
{
    if (!m || !g)
        return;

    double g_ref = (g->mean_ns > 0.0001) ? g->mean_ns : 0.0001;
    double factor = m->mean_ns / g_ref;

    const char *ratio_color = GREEN;
    if (factor > 3.0)
        ratio_color = BOLD BRIGHT_RED;
    else if (factor > 1.2)
        ratio_color = BOLD BRIGHT_YELLOW;

    printf("  " WHITE "%-21s" RESET "│" BOLD CYAN " %10.1f " RESET "│" CYAN " %10.1f " RESET "│" DIM WHITE " %10.1f " RESET "│" BRIGHT_PURPLE " %10.1f " RESET "│" DIM BRIGHT_PURPLE " %10.1f " RESET "│" DIM WHITE " %10.1f " RESET "│"
           " %s%8.2fx " RESET "\n",
           name,
           m->mean_ns, m->min_ns, m->stddev_ns,
           g->mean_ns, g->min_ns, g->stddev_ns,
           ratio_color, factor);
}

void print_suite_summary(int total_fails)
{
    if (total_fails == 0)
        printf("\n" BADGE_PASS BOLD GREEN "All configured tests passed successfully!" RESET "\n");
    else
        printf("\n" BADGE_FAIL BOLD RED "Benchmarks skipped due to %d failing test suite(s)." RESET "\n", total_fails);
}

void print_diag_hex(const char *label, const mprec_int *m)
{
    printf("  %-14s = 0x", label);
    if (!m || !m->d || m->size == 0)
    {
        printf("0 (NULL/Empty)\n");
        return;
    }
    int top = m->size - 1;
    while (top > 0 && m->d[top] == 0)
        top--;

    printf("%lx", (unsigned long)m->d[top]);
    for (int i = top - 1; i >= 0; i--)
        printf("%016lx", (unsigned long)m->d[i]);
    printf("  (bits: %lu, limbs: %d)\n", (unsigned long)int_bit_length(m), m->size);
}

bool gmp_equals_mprec(const mpz_t g, const mprec_int *m)
{
    if (mpz_sgn(g) == 0)
        return int_bit_length(m) == 0;

    INTEGER_STACK_ALLOC(tmp, m->size * 64);
    memset(tmp.d, 0, (size_t)tmp.size * sizeof(uint64_t));

    size_t count = 0;
    mpz_export(tmp.d, &count, -1, 8, 0, 0, g);

    for (int i = 0; i < m->size; i++)
    {
        if (m->d[i] != tmp.d[i])
            return false;
    }
    return true;
}

// ============================================================================
// GENERIC FUZZ DRIVERS
// ============================================================================

int driver_fuzz_bin(const char *name, int iters, bin_fn_t fn, gmp_bin_fn_t gmp_fn)
{
    mpz_t ga, gb, gr;
    mpz_inits(ga, gb, gr, NULL);

    INTEGER_STACK_ALLOC(a, 1024);
    INTEGER_STACK_ALLOC(b, 1024);
    INTEGER_STACK_ALLOC(r, 2048);

    int fails = 0;
    for (int i = 0; i < iters; i++)
    {
        random_number(&a, 128 + (rand() % 384));
        random_number(&b, 64 + (rand() % 256));

        mprec_to_gmp(ga, &a);
        mprec_to_gmp(gb, &b);
        gmp_fn(gr, ga, gb);

        memset(r.d, 0, (size_t)r.size * sizeof(uint64_t));

        bool ok = fn(&r, &a, &b);
        bool match = ok && gmp_equals_mprec(gr, &r);

        if (!match)
        {
            printf("\n" BADGE_FAIL BOLD RED "%s mismatch on run %d!" RESET "\n", name, i);
            printf("  Function returned: %s\n", ok ? "true" : "false (ERROR)");
            print_diag_hex("Operand A", &a);
            print_diag_hex("Operand B", &b);
            print_diag_hex("Your Output", &r);
            gmp_printf("  GMP Oracle     = 0x%Zx  (bits: %zu)\n", gr, mpz_sizeinbase(gr, 2));
            fails++;
            break;
        }
    }

    mpz_clears(ga, gb, gr, NULL);
    return fails;
}

int driver_fuzz_tern(const char *name, int iters, tern_fn_t fn, gmp_tern_fn_t gmp_fn)
{
    mpz_t ga, gb, gn, gr;
    mpz_inits(ga, gb, gn, gr, NULL);

    INTEGER_STACK_ALLOC(a, 1024);
    INTEGER_STACK_ALLOC(b, 1024);
    INTEGER_STACK_ALLOC(n, 1024);
    INTEGER_STACK_ALLOC(r, 2048);

    int fails = 0;
    for (int i = 0; i < iters; i++)
    {
        random_number(&a, 128 + (rand() % 384));
        random_number(&b, 128 + (rand() % 384));
        random_number(&n, 128 + (rand() % 384));

        mprec_to_gmp(ga, &a);
        mprec_to_gmp(gb, &b);
        mprec_to_gmp(gn, &n);
        gmp_fn(gr, ga, gb, gn);

        memset(r.d, 0, (size_t)r.size * sizeof(uint64_t));

        bool ok = fn(&r, &a, &b, &n);
        bool match = ok && gmp_equals_mprec(gr, &r);

        if (!match)
        {
            printf("\n" BADGE_FAIL BOLD RED "%s mismatch on run %d!" RESET "\n", name, i);
            printf("  Function returned: %s\n", ok ? "true" : "false (ERROR)");
            print_diag_hex("Operand A", &a);
            print_diag_hex("Operand B", &b);
            print_diag_hex("Modulus/Arg N", &n);
            print_diag_hex("Your Output", &r);
            gmp_printf("  GMP Oracle     = 0x%Zx  (bits: %zu)\n", gr, mpz_sizeinbase(gr, 2));
            fails++;
            break;
        }
    }

    mpz_clears(ga, gb, gn, gr, NULL);
    return fails;
}

int driver_fuzz_shift(const char *name, int iters, shift_fn_t fn, gmp_shift_fn_t gmp_fn)
{
    mpz_t ga, gr;
    mpz_inits(ga, gr, NULL);

    INTEGER_STACK_ALLOC(a, 1024);
    INTEGER_STACK_ALLOC(r, 2048);

    int fails = 0;
    for (int i = 0; i < iters; i++)
    {
        random_number(&a, 128 + (rand() % 384));
        int shift = rand() % 512;

        mprec_to_gmp(ga, &a);
        gmp_fn(gr, ga, (mp_bitcnt_t)shift);

        memset(r.d, 0, (size_t)r.size * sizeof(uint64_t));

        bool ok = fn(&r, &a, shift);
        bool match = ok && gmp_equals_mprec(gr, &r);

        if (!match)
        {
            printf("\n" BADGE_FAIL BOLD RED "%s << %d mismatch on run %d!" RESET "\n", name, shift, i);
            printf("  Function returned: %s\n", ok ? "true" : "false (ERROR)");
            print_diag_hex("Operand A", &a);
            print_diag_hex("Your Output", &r);
            gmp_printf("  GMP Oracle     = 0x%Zx  (bits: %zu)\n", gr, mpz_sizeinbase(gr, 2));
            fails++;
            break;
        }
    }

    mpz_clears(ga, gr, NULL);
    return fails;
}

// ============================================================================
// STATISTICAL BENCHMARK DRIVERS
// ============================================================================

void driver_bench_bin(bin_fn_t fn, gmp_bin_fn_t gmp_fn, int bits, int iters, BenchStats *mprec_st, BenchStats *gmp_st)
{
    INTEGER_STACK_ALLOC(a, bits);
    INTEGER_STACK_ALLOC(b, bits);
    INTEGER_STACK_ALLOC(r, bits * 2);
    mpz_t ga, gb, gr;
    mpz_inits(ga, gb, gr, NULL);

    double m_samples[BENCH_SAMPLES];
    double g_samples[BENCH_SAMPLES];

    // Warm-up cache
    random_number(&a, bits);
    random_number(&b, bits > 64 ? bits / 2 : bits);
    mprec_to_gmp(ga, &a);
    mprec_to_gmp(gb, &b);
    for (int i = 0; i < (iters > 100 ? 50 : 2); i++)
    {
        fn(&r, &a, &b);
        gmp_fn(gr, ga, gb);
    }

    for (int s = 0; s < BENCH_SAMPLES; s++)
    {
        random_number(&a, bits);
        random_number(&b, bits > 64 ? bits / 2 : bits);
        mprec_to_gmp(ga, &a);
        mprec_to_gmp(gb, &b);

        double t0 = get_ns();
        for (int i = 0; i < iters; i++)
            fn(&r, &a, &b);
        m_samples[s] = (get_ns() - t0) / (double)iters;

        t0 = get_ns();
        for (int i = 0; i < iters; i++)
            gmp_fn(gr, ga, gb);
        g_samples[s] = (get_ns() - t0) / (double)iters;
    }

    compute_stats(m_samples, BENCH_SAMPLES, mprec_st);
    compute_stats(g_samples, BENCH_SAMPLES, gmp_st);
    mpz_clears(ga, gb, gr, NULL);
}

void driver_bench_tern(tern_fn_t fn, gmp_tern_fn_t gmp_fn, int bits, int iters, BenchStats *mprec_st, BenchStats *gmp_st)
{
    INTEGER_STACK_ALLOC(a, bits);
    INTEGER_STACK_ALLOC(b, bits);
    INTEGER_STACK_ALLOC(n, bits);
    INTEGER_STACK_ALLOC(r, bits * 2);
    mpz_t ga, gb, gn, gr;
    mpz_inits(ga, gb, gn, gr, NULL);

    double m_samples[BENCH_SAMPLES];
    double g_samples[BENCH_SAMPLES];

    // Warm-up cache
    random_number(&a, bits);
    random_number(&b, bits);
    random_number(&n, bits);
    mprec_to_gmp(ga, &a);
    mprec_to_gmp(gb, &b);
    mprec_to_gmp(gn, &n);
    for (int i = 0; i < (iters > 100 ? 50 : 2); i++)
    {
        fn(&r, &a, &b, &n);
        gmp_fn(gr, ga, gb, gn);
    }

    for (int s = 0; s < BENCH_SAMPLES; s++)
    {
        random_number(&a, bits);
        random_number(&b, bits);
        random_number(&n, bits);
        mprec_to_gmp(ga, &a);
        mprec_to_gmp(gb, &b);
        mprec_to_gmp(gn, &n);

        double t0 = get_ns();
        for (int i = 0; i < iters; i++)
            fn(&r, &a, &b, &n);
        m_samples[s] = (get_ns() - t0) / (double)iters;

        t0 = get_ns();
        for (int i = 0; i < iters; i++)
            gmp_fn(gr, ga, gb, gn);
        g_samples[s] = (get_ns() - t0) / (double)iters;
    }

    compute_stats(m_samples, BENCH_SAMPLES, mprec_st);
    compute_stats(g_samples, BENCH_SAMPLES, gmp_st);
    mpz_clears(ga, gb, gn, gr, NULL);
}

void driver_bench_shift(shift_fn_t fn, gmp_shift_fn_t gmp_fn, int bits, int iters, BenchStats *mprec_st, BenchStats *gmp_st)
{
    INTEGER_STACK_ALLOC(a, bits);
    INTEGER_STACK_ALLOC(r, bits * 2);
    mpz_t ga, gr;
    mpz_inits(ga, gr, NULL);
    int shift = 35;

    double m_samples[BENCH_SAMPLES];
    double g_samples[BENCH_SAMPLES];

    for (int s = 0; s < BENCH_SAMPLES; s++)
    {
        random_number(&a, bits);
        mprec_to_gmp(ga, &a);

        double t0 = get_ns();
        for (int i = 0; i < iters; i++)
            fn(&r, &a, shift);
        m_samples[s] = (get_ns() - t0) / (double)iters;

        t0 = get_ns();
        for (int i = 0; i < iters; i++)
            gmp_fn(gr, ga, (mp_bitcnt_t)shift);
        g_samples[s] = (get_ns() - t0) / (double)iters;
    }

    compute_stats(m_samples, BENCH_SAMPLES, mprec_st);
    compute_stats(g_samples, BENCH_SAMPLES, gmp_st);
    mpz_clears(ga, gr, NULL);
}

// ============================================================================
// REGISTRY AUTOMATION
// ============================================================================

int run_registry_tests(const FuncEntry *registry, int count)
{
    int total_failures = 0;
    for (int i = 0; i < count; i++)
    {
        const FuncEntry *e = &registry[i];
        printf(BADGE_RUN CYAN "%-20s vs GMP (%d runs)... " RESET, e->name, e->test_iters);
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

void run_registry_benchmarks(const FuncEntry *registry, int count, int bits)
{
    print_bench_header(bits);
    for (int i = 0; i < count; i++)
    {
        const FuncEntry *e = &registry[i];
        BenchStats mprec_st = {0}, gmp_st = {0};

        if (e->kind == OP_BINARY)
            driver_bench_bin((bin_fn_t)e->fn, (gmp_bin_fn_t)e->gmp_fn, bits, e->bench_iters, &mprec_st, &gmp_st);
        else if (e->kind == OP_TERNARY)
            driver_bench_tern((tern_fn_t)e->fn, (gmp_tern_fn_t)e->gmp_fn, bits, e->bench_iters, &mprec_st, &gmp_st);
        else if (e->kind == OP_SHIFT)
            driver_bench_shift((shift_fn_t)e->fn, (gmp_shift_fn_t)e->gmp_fn, bits, e->bench_iters, &mprec_st, &gmp_st);

        print_bench_row(e->name, &mprec_st, &gmp_st);
    }
}