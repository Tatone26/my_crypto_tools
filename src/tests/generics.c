#include "tests.h"
#include <stdlib.h>

// Generic Fuzz Driver: Binary operations r = f(a, b)
int driver_fuzz_bin(const char *name, int iters, bin_fn_t fn, gmp_bin_fn_t gmp_fn)
{
    mpz_t ga, gb, gr;
    mpz_inits(ga, gb, gr, NULL);

    INTEGER_STACK_ALLOC(a, 512);
    INTEGER_STACK_ALLOC(b, 256);
    INTEGER_STACK_ALLOC(r, 512);

    int fails = 0;
    for (int i = 0; i < iters; i++)
    {
        random_number(&a, 256 + (rand() % 256));
        random_number(&b, 64 + (rand() % 192));

        mprec_to_gmp(ga, &a);
        mprec_to_gmp(gb, &b);
        gmp_fn(gr, ga, gb);

        if (!fn(&r, &a, &b) || !gmp_equals_mprec(gr, &r))
        {
            printf("\n" BADGE_FAIL "%s mismatch on run %d!\n", name, i);
            fails++;
            break;
        }
    }

    mpz_clears(ga, gb, gr, NULL);
    return fails;
}

// Generic Fuzz Driver: Ternary operations r = f(a, b, n)
int driver_fuzz_tern(const char *name, int iters, tern_fn_t fn, gmp_tern_fn_t gmp_fn)
{
    mpz_t ga, gb, gn, gr;
    mpz_inits(ga, gb, gn, gr, NULL);

    INTEGER_STACK_ALLOC(a, 512);
    INTEGER_STACK_ALLOC(b, 512);
    INTEGER_STACK_ALLOC(n, 512);
    INTEGER_STACK_ALLOC(r, 1024);

    int fails = 0;
    for (int i = 0; i < iters; i++)
    {
        random_number(&a, 256 + (rand() % 256));
        random_number(&b, 256 + (rand() % 256));
        random_number(&n, 256 + (rand() % 256));

        mprec_to_gmp(ga, &a);
        mprec_to_gmp(gb, &b);
        mprec_to_gmp(gn, &n);
        gmp_fn(gr, ga, gb, gn);

        if (!fn(&r, &a, &b, &n) || !gmp_equals_mprec(gr, &r))
        {
            printf("\n" BADGE_FAIL "%s mismatch on run %d!\n", name, i);
            fails++;
            break;
        }
    }

    mpz_clears(ga, gb, gn, gr, NULL);
    return fails;
}

// Generic Benchmark Driver: Binary operations
void driver_bench_bin(bin_fn_t fn, gmp_bin_fn_t gmp_fn, int bits, int iters, double *mprec_ns, double *gmp_ns)
{
    INTEGER_STACK_ALLOC(a, bits);
    INTEGER_STACK_ALLOC(b, bits / 2);
    INTEGER_STACK_ALLOC(r, bits);
    random_number(&a, bits);
    random_number(&b, bits / 2);

    mpz_t ga, gb, gr;
    mpz_inits(ga, gb, gr, NULL);
    mprec_to_gmp(ga, &a);
    mprec_to_gmp(gb, &b);

    double t0 = get_ns();
    for (int i = 0; i < iters; i++)
        fn(&r, &a, &b);
    *mprec_ns = (get_ns() - t0) / iters;

    t0 = get_ns();
    for (int i = 0; i < iters; i++)
        gmp_fn(gr, ga, gb);
    *gmp_ns = (get_ns() - t0) / iters;

    mpz_clears(ga, gb, gr, NULL);
}

// Generic Benchmark Driver: Ternary operations
void driver_bench_tern(tern_fn_t fn, gmp_tern_fn_t gmp_fn, int bits, int iters, double *mprec_ns, double *gmp_ns)
{
    INTEGER_STACK_ALLOC(a, bits);
    INTEGER_STACK_ALLOC(b, bits);
    INTEGER_STACK_ALLOC(n, bits);
    INTEGER_STACK_ALLOC(r, bits * 2);
    random_number(&a, bits);
    random_number(&b, bits);
    random_number(&n, bits);

    mpz_t ga, gb, gn, gr;
    mpz_inits(ga, gb, gn, gr, NULL);
    mprec_to_gmp(ga, &a);
    mprec_to_gmp(gb, &b);
    mprec_to_gmp(gn, &n);

    double t0 = get_ns();
    for (int i = 0; i < iters; i++)
        fn(&r, &a, &b, &n);
    *mprec_ns = (get_ns() - t0) / iters;

    t0 = get_ns();
    for (int i = 0; i < iters; i++)
        gmp_fn(gr, ga, gb, gn);
    *gmp_ns = (get_ns() - t0) / iters;

    mpz_clears(ga, gb, gn, gr, NULL);
}

// Generic Fuzz Driver: Shift operations r = f(a, shift)
int driver_fuzz_shift(const char *name, int iters, shift_fn_t fn, gmp_shift_fn_t gmp_fn)
{
    mpz_t ga, gr;
    mpz_inits(ga, gr, NULL);

    INTEGER_STACK_ALLOC(a, 512);
    INTEGER_STACK_ALLOC(r, 1024);

    int fails = 0;
    for (int i = 0; i < iters; i++)
    {
        random_number(&a, 256 + (rand() % 256));
        int shift = rand() % 512;

        mprec_to_gmp(ga, &a);
        gmp_fn(gr, ga, (mp_bitcnt_t)shift);

        if (!fn(&r, &a, shift) || !gmp_equals_mprec(gr, &r))
        {
            printf("\n" BADGE_FAIL "%s << %d mismatch on run %d!\n", name, shift, i);
            fails++;
            break;
        }
    }

    mpz_clears(ga, gr, NULL);
    return fails;
}

// Generic Benchmark Driver: Shift operations
void driver_bench_shift(shift_fn_t fn, gmp_shift_fn_t gmp_fn, int bits, int iters, double *mprec_ns, double *gmp_ns)
{
    INTEGER_STACK_ALLOC(a, bits);
    INTEGER_STACK_ALLOC(r, bits * 2);
    random_number(&a, bits);

    int shift = 35; // Representative non-limb-aligned shift

    mpz_t ga, gr;
    mpz_inits(ga, gr, NULL);
    mprec_to_gmp(ga, &a);

    double t0 = get_ns();
    for (int i = 0; i < iters; i++)
        fn(&r, &a, shift);
    *mprec_ns = (get_ns() - t0) / iters;

    t0 = get_ns();
    for (int i = 0; i < iters; i++)
        gmp_fn(gr, ga, (mp_bitcnt_t)shift);
    *gmp_ns = (get_ns() - t0) / iters;

    mpz_clears(ga, gr, NULL);
}