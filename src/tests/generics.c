#include "tests.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

static void print_diag_hex(const char *label, const mprec_int *m)
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
        // Varied input lengths
        random_number(&a, 128 + (rand() % 384));
        random_number(&b, 64 + (rand() % 256));

        mprec_to_gmp(ga, &a);
        mprec_to_gmp(gb, &b);
        gmp_fn(gr, ga, gb);

        for (int l = 0; l < r.size; l++)
            r.d[l] = 0;

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

        for (int l = 0; l < r.size; l++)
            r.d[l] = 0;

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

        for (int l = 0; l < r.size; l++)
            r.d[l] = 0;

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

void driver_bench_bin(bin_fn_t fn, gmp_bin_fn_t gmp_fn, int bits, int iters, double *mprec_ns, double *gmp_ns)
{
    INTEGER_STACK_ALLOC(a, bits);
    INTEGER_STACK_ALLOC(b, bits);
    INTEGER_STACK_ALLOC(r, bits * 2);
    random_number(&a, bits);
    random_number(&b, bits > 64 ? bits / 2 : bits);

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

void driver_bench_shift(shift_fn_t fn, gmp_shift_fn_t gmp_fn, int bits, int iters, double *mprec_ns, double *gmp_ns)
{
    INTEGER_STACK_ALLOC(a, bits);
    INTEGER_STACK_ALLOC(r, bits * 2);
    random_number(&a, bits);

    int shift = 35;

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